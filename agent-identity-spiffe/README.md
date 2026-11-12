# Agent Identity with SPIFFE

Find the workloads on your infrastructure (AI agents, MCP servers, Kubernetes pods, local processes, containers and network services), propose a [SPIFFE](https://spiffe.io) identity for each one, have a person approve it, then issue it from a small SPIFFE-style server.

This is a learning project. The server is a readable CA of about 300 lines, not SPIRE. The [What this is not](#what-this-is-not) section lists what's missing.

```
           discovery sources (each opt-in, each configured explicitly)
  ┌───────────┬────────────┬───────────┬──────────┬──────────┐
  │ ai_agents │ kubernetes │ processes │  docker  │ network  │
  └─────┬─────┴──────┬─────┴─────┬─────┴────┬─────┴────┬─────┘
        └────────────┴───── workloads ──────┴──────────┘
                              │   (observed facts + selectors)
                              ▼
                   policy rules (first match wins)
                              │
              unmatched? ──► optional Claude proposer
                              │   (only allow-listed attributes leave the machine;
                              │    may answer "insufficient data")
                              ▼
                  HUMAN APPROVAL GATE  (y / n / quit)
                              │
                              ▼
            spiffe-server: registration entry ──► X.509-SVID / JWT-SVID
                              (no entry, no identity)
```

## Layout

```
spiffe_identity/
  spiffeid.py          parse/validate SPIFFE IDs, sanitize path segments
  ca.py                CA: X.509-SVIDs, JWT-SVIDs (ES256), trust bundle + JWKS, verifiers
  registry.py          registration entries (JSON file), approved_by required
  server.py            HTTPS admin API around the CA + registry
  client.py            client for that API (key generated locally, only the CSR is sent)
  discovery/
    ai_agents.py       A2A agent cards + MCP configs on disk, A2A /.well-known probes
    kubernetes.py      pods via the K8s REST API (read-only)
    processes.py       Linux procfs or ps (macOS), filtered by your include patterns
    docker.py          containers via the Docker Engine socket (read-only)
    network.py         TCP connect scan of ranges you list
  policy.py            rule-based ID assignment
  classifier.py        optional Claude proposer for workloads no rule matched
  approval.py          the human approval gate
  cli.py               agent-discovery: discover / plan / apply / entries / jwt / verify-*
examples/
  demo.config.json     localhost demo against the made-up fixtures below
  config.template.json every option, with <placeholders> you fill in
  manifests/           DEMO FIXTURES: one A2A agent card, one MCP config (made up)
scripts/               setup.sh (venv + install), demo.sh (full flow)
tests/                 49 tests, no network access needed
```

## Quickstart (demo, localhost only)

You need Python 3.10 or newer. Check with `python3 --version`. `setup.sh` checks too, and tells you what to do if yours is too old.

```bash
cd agent-identity-spiffe
./scripts/setup.sh
```

```bash
source .venv/bin/activate
```

```bash
./scripts/demo.sh
```

The demo starts the server, scans only `examples/manifests/`, proposes three identities and leaves one MCP server unassigned on purpose. That server has no command or URL, so there isn't enough data to name it. You then approve or reject each proposal, and the demo verifies the SVIDs it issued. Everything it writes goes to `.data/` and `out/`, both git-ignored. Delete them to start over.

Here are the same steps run by hand:

```bash
export SPIFFE_ADMIN_TOKEN=$(python -c 'import secrets; print(secrets.token_urlsafe(32))')
```

```bash
spiffe-server --config examples/demo.config.json
```

In a second terminal (export the same token there):

```bash
agent-discovery plan  --config examples/demo.config.json
```

```bash
agent-discovery apply --config examples/demo.config.json --approver "your-name" --issue-dir out/
```

```bash
agent-discovery verify-x509 --cert out/demo.local_ai-agent_Ticket-Triage-Agent/svid.pem --bundle .data/demo/bundle.pem
```

```bash
agent-discovery jwt --config examples/demo.config.json --spiffe-id spiffe://demo.local/ai-agent/Ticket-Triage-Agent --audience ticket-api
```

`python -m spiffe_identity.cli ...` and `python -m spiffe_identity.server ...` work without installing, as long as you run them from this folder.

## macOS notes

- **Python:** the `python3` that ships with macOS may be too old (3.9). Install a newer one with `brew install python@3.12`, then run `PYTHON=python3.12 ./scripts/setup.sh`.
- **Processes source:** use `"method": "ps"`. The `"procfs"` method reads Linux `/proc`, which macOS doesn't have. With `ps`, processes you don't own show up but may be missing an executable path, and the tool warns you when it can't read one.
- **Docker Desktop:** the socket is often `~/.docker/run/docker.sock` rather than `/var/run/docker.sock`. Check Docker Desktop's settings for the path on your machine. `~` is expanded in the config.
- **TLS to other hosts:** if you installed Python from python.org and A2A probes or the Kubernetes source fail with `CERTIFICATE_VERIFY_FAILED`, run the `Install Certificates.command` that came with that Python. The SPIFFE server and its client aren't affected, because they trust the server's own `bundle.pem`.

## Using it on your own systems

Copy `examples/config.template.json` and fill in every `<...>` value. Delete the discovery sources you don't want. The design rule throughout is that **nothing is guessed**:

- There is no default trust domain, scan range, namespace, process filter or socket path. A missing value stops the tool with an error that names the key.
- A source that isn't listed under `discovery` never runs. A misspelled source name is an error, not a silent no-op.
- A policy placeholder with no value, such as a pod with no service account, leaves that workload **unassigned**. The proposal says which value was missing.
- The Claude step may (and is told to) answer "insufficient data". Those workloads stay unassigned too.

### Discovery sources

| Source | What it reads | Selectors it produces | Needs |
|---|---|---|---|
| `ai_agents` | A2A agent cards (`agent-card.json`, `agent.json`), MCP configs (`.mcp.json`, `mcp.json`, `claude_desktop_config.json`), A2A `/.well-known/agent-card.json` on URLs you list | `ai:a2a-card:<path or url>`, `ai:agent-name:…`, `ai:mcp-config:<path>`, `ai:mcp-server:…` | read access to the dirs |
| `kubernetes` | `GET /api/v1/namespaces/<ns>/pods` | `k8s:ns:…`, `k8s:sa:…`, `k8s:pod-label:k:v` | a token with `list pods` |
| `processes` | `"method": "procfs"`: `/proc/<pid>/…` (Linux). `"method": "ps"`: `ps -axww` output (macOS, Linux) | `unix:uid:…`, `unix:comm:…`, `unix:path:…` | same user or root to read `exe` |
| `docker` | `GET /containers/json` on the Engine socket | `docker:image_id:…`, `docker:label:k:v` | access to the socket |
| `network` | TCP connect to the CIDRs and ports you list (no payload, no credentials) | `net:addr:ip:port` | authorization to scan that range |

Some notes on the data:

- MCP server `args` and `env` are **counted, never copied**, because they often hold tokens.
- Process command lines are stored locally. They're only sent to the LLM if you put `cmdline` in `llm.send_attributes`.
- `network` selectors are the weakest kind: anything that takes over that IP address inherits the identity. The approval prompt warns you about this.
- Only scan networks you own or are explicitly authorized to scan. `max_hosts` caps how many addresses a scan will touch.

### Policy rules

Rules are checked in order and the first match wins. Each `match` value is a glob:

```json
{"name": "k8s-by-sa",
 "match": {"kind": "k8s-pod", "attributes": {"namespace": "agents-*"}},
 "spiffe_id_path": "/k8s/ns/{attr.namespace}/sa/{attr.service_account}"}
```

You can use the placeholders `{name}`, `{kind}`, `{source}` and `{attr.<key>}`. Each value is sanitized into a valid SPIFFE path segment. Run `agent-discovery discover --config … --json` to see which attributes each workload actually has.

### Optional Claude proposer

For workloads no rule matched, set `"llm": {"enabled": true, ...}` and provide an Anthropic credential (`ANTHROPIC_API_KEY` or `ant auth login`). It uses `claude-opus-5-5` by default, which you can change with `llm.model`. Server-side refusal fallbacks are enabled (`fallbacks: "default"`). Guard rails:

- `llm.send_attributes` is **required**. Only those attribute keys are sent, and `[]` sends none.
- Attributes are framed as untrusted data, because a pod label or agent card could contain text written to look like instructions.
- The output is constrained to a JSON schema. Every proposed path is re-validated locally, and invalid ones are dropped.
- LLM proposals are labelled `llm:<model>` and still go through the approval gate.
- Override per run with `--llm` / `--no-llm`.

The LLM path is covered by unit tests with a fake client. It has **not** been run against the live API in this repo.

### The approval gate

`apply` asks y/n/quit for every proposal and records `--approver` on each registration entry. If stdin isn't a terminal, it approves nothing. `--approve-all` exists for demos and tests only, so don't put it in a cron job pointed at real infrastructure.

## Server API

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/healthz` | – | liveness + trust domain |
| GET | `/v1/bundle` | – | X.509 trust bundle (PEM) |
| GET | `/v1/bundle/jwks` | – | JWT trust bundle (JWKS) |
| GET | `/v1/entries` | admin | list registration entries |
| POST | `/v1/entries` | admin | create an entry (`approved_by` required) |
| DELETE | `/v1/entries/<id>` | admin | delete an entry |
| POST | `/v1/svid/x509` | admin | sign a CSR into an X.509-SVID for a **registered** ID |
| POST | `/v1/svid/jwt` | admin | mint a JWT-SVID for a **registered** ID |

The server serves TLS using its own SVID (`spiffe://<td>/spiffe-server`, plus the DNS and IP names you configure). Clients verify it against `<data_dir>/bundle.pem`, which the server writes on startup.

The SVIDs follow the SPIFFE specs: an X.509-SVID has exactly one URI SAN, is not a CA, and has no `keyCertSign`. A JWT-SVID is signed with ES256 and carries `sub`, `aud` and `exp`. Lifetimes never extend past the CA's own expiry. The CA ignores whatever SANs a CSR asks for.

## What this is not

- **No workload attestation.** This is the big one. SPIRE's agent proves *which process* is asking (by kernel PID, K8s pod UID and so on) before it hands over an SVID. Here, whoever holds the admin token can mint an SVID for any registered ID. The token is the root of trust: keep it secret, and keep the server on a network you control.
- No Workload API (the SPIFFE Unix-socket API workloads normally fetch SVIDs from). SVIDs are written to files instead.
- No key rotation, no upstream CA, no HSM, no federation and no revocation. The CA key is a file on disk (mode 0600).
- Selectors are recorded on entries but aren't re-checked when an SVID is issued.

If you need these, the natural next step is to keep the discovery and policy half of this project and swap the server for a real [SPIRE](https://github.com/spiffe/spire) server, creating entries through its registration API.

## Tests

```bash
pip install -r requirements-dev.txt
```

```bash
python -m pytest -q
```

The tests use fake procfs trees, fake K8s and Docker responses, and a fake Anthropic client. One test starts the real HTTPS server on a free localhost port.
