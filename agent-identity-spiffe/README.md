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
  pipeline.py          discover -> policy -> LLM, and the saved-scan snapshot (shared by CLI + portal)
  nodes.py             device (node) attestation: enrolled keys, one-time challenges, evidence, confidence
  lifecycle.py         issuance log, revocation (signed CRL + JWT list, fail-closed checker), delegation grants
  toolpolicy.py        deny-by-default tool policy: the single gate every action passes through
  trace.py             the trace file: every decision, result, run and log line as JSON
  portal.py            local web portal (localhost only): view, scan, approve, revoke
  portal_static/       the portal page (HTML, CSS, JS; no external downloads)
  cli.py               agent-discovery: discover / plan / apply / portal / entries / jwt / verify-*
examples/
  demo.config.json     localhost demo against the made-up fixtures below
  demo.tool-policy.json   tool policy for the demo (allows only what the demo needs)
  laptop.config.json   scans YOUR computer: Claude Desktop, Claude Code (~/.claude.json), agent processes
  laptop.tool-policy.json tool policy for laptop.config.json (reads only those two places; all features on)
  tool-policy.template.json every tool and limit, with <placeholders>
  config.template.json every option, with <placeholders> you fill in
  manifests/           DEMO FIXTURES: one A2A agent card, one MCP config (made up)
scripts/               setup.sh (venv + install), demo.sh (full flow in the terminal), portal.sh (server + portal),
                       dev_fake_node_agent.py (TEST ONLY: software-key stand-in for the Mac node agent)
tests/                 134 tests, no network access needed
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
agent-discovery verify-x509 --cert out/demo.local_ai-agent_Ticket-Triage-Agent/svid.pem --bundle .data/demo/bundle.pem --server https://127.0.0.1:8443
```

```bash
agent-discovery jwt --config examples/demo.config.json --spiffe-id spiffe://demo.local/ai-agent/Ticket-Triage-Agent --audience ticket-api
```

`python -m spiffe_identity.cli ...` and `python -m spiffe_identity.server ...` work without installing, as long as you run them from this folder.

## Run it on your own computer (detect your real agents)

The demo only scans made-up files. To scan **your** machine instead:

```bash
export SPIFFE_ADMIN_TOKEN=$(python -c 'import secrets; print(secrets.token_urlsafe(32))')
```

```bash
CONFIG=examples/laptop.config.json ./scripts/portal.sh "Your Name"
```

Then click **Scan now**. `examples/laptop.config.json` looks in:

| Where | What it finds |
|---|---|
| `~/Library/Application Support/Claude/claude_desktop_config.json` | Claude Desktop's MCP servers |
| `~/.claude.json` | Claude Code's MCP servers, both user-wide and per-project (shown with the project path) |
| `../../job-search-agent/agent-card.json` | the Job Search Agent's card (name, skills); if `python app.py` is running **from that folder**, the process is merged into it, so it shows as one **ai-agent** marked running |
| `examples/manifests/` | the made-up demo agents, shown with a **DEMO** tag so they can't be confused with real ones |
| Running processes (`ps`) | Python / Node / `npx` / `uvx` processes whose command line contains `app.py`, `mcp` or `modelcontextprotocol`, e.g. the Job Search Agent started with `python app.py`, or running MCP servers |

**Agents, MCP servers and processes:** the *kind* column says how something was found.
- **ai-agent:** it has an agent card.
- **mcp-server:** an app's MCP config lists it.
- **process:** only the OS process list shows it.

When a running process's working folder contains an agent card, the two are **merged** into one ai-agent (attribute `running: yes`, plus the process's pid, executable and folder). An interpreter's path (Python, Node…) identifies the interpreter, not your app, so it never raises confidence above Low.

**Notes:**
- **Only those places are read.** The tool policy (`examples/laptop.tool-policy.json`) allows reading only those two paths. Everything else (other folders, Docker, Kubernetes, network scans, the LLM) is blocked, and every read is in the trace.
- **Secrets aren't kept:**
  - MCP server arguments and environment variables are **counted, not copied**,
  - query strings and `user:password@` are **removed from URLs**,
  - nothing else in `~/.claude.json` is kept.
- **Separate data:** it uses `.data/laptop`, so demo data doesn't mix in. Delete that folder to start over.
- **To scan more places** (e.g. `.mcp.json` files in your code folders): add the folder to `manifest_dirs` in the config **and** to `discovery.ai_agents.read_manifests.paths` in the policy. Both are needed; the policy decides.
- **"0 workloads"** with a warning like "not a directory" just means that app isn't installed or has no MCP servers configured.

## The portal

A local web page that shows every discovered workload, its attributes and selectors, the identity proposed for it, and whether that identity is registered. You can scan, approve and revoke from it.

```bash
./scripts/portal.sh "Your Name"
```

This starts the SPIFFE server and the portal for the demo config, then opens http://127.0.0.1:8765/ in your browser. The name you pass is recorded as `approved_by` on every identity you approve. Press Ctrl+C to stop both.

With your own config, run the server yourself, then:

```bash
agent-discovery portal --config yours.json --approver "Your Name"
```

Your config needs a `portal` section:

```json
"portal": {"listen_host": "127.0.0.1", "listen_port": 8765, "scan_file": "<where the last scan is saved>"}
```

What it shows and does:

- **On load:** the last saved scan. `plan`, `apply` and the portal's **Scan now** button all save to `portal.scan_file`. It also shows the entries currently on the SPIFFE server.
- **Workload rows:** click one to see all its attributes, selectors, which rule (or the LLM) chose the identity and why, and who approved it.
- **Approve:** registers the proposed identity on the server. It asks you to confirm first, and flags LLM proposals and weak IP:port selectors.
- **Revoke:** deletes the registration entry, so the server stops issuing SVIDs for it. SVIDs already issued stay valid until they expire, because this learning server has no revocation list.
- **Server down:** if the SPIFFE server is unreachable, registration status shows as **Unknown** and the page says why, instead of guessing.

There's no login, so the portal protects itself in other ways:

- It refuses to start on anything but a loopback address (`127.0.0.1`, `::1`, `localhost`), so other machines can't reach it.
- Requests must name that address in the `Host` header. This blocks DNS rebinding, where another website points its own hostname at your machine.
- Scan, approve and revoke need a random per-run token that's embedded in the page and sent as a header. Other websites open in your browser can't read it, which blocks cross-site request forgery.
- All workload data is inserted as text, never HTML, and a strict Content Security Policy blocks inline and external scripts. Agent cards and labels are untrusted input.

## Tool policy and trace

Every action the agent, portal or identity server can take is a **tool**. A separate file, the **tool policy**, lists the tools that are allowed and their limits; **everything else is blocked**. Every action, allowed or denied, is written to one **trace file**.

The config points at the policy:

```json
"tool_policy_file": "demo.tool-policy.json"
```

A policy looks like this:

```json
{
  "version": 1,
  "default": "deny",
  "trace": {"file": "../.data/demo/trace.jsonl"},
  "tools": {
    "discovery.ai_agents.read_manifests": {"paths": ["manifests"]},
    "server.connect": {"urls": ["https://127.0.0.1:8443"]},
    "server.entries.list": {},
    "server.entries.create": {"spiffe_id_prefixes": ["spiffe://demo.local/ai-agent/"]}
  }
}
```

### Tools and their required limits

| Tool | Limits (all required unless marked) | Used by |
|---|---|---|
| `discovery.ai_agents.read_manifests` | `paths`: folders the scanner may read. Every manifest file is checked too, so a symlink can't reach outside. | agent, portal |
| `discovery.ai_agents.probe_a2a` | `origins`: e.g. `https://agents.example.com`. Redirects are checked against the same list. | agent, portal |
| `discovery.kubernetes.list_pods` | `api_servers`, `namespaces`. Redirects are refused, so the token only goes to the listed server. | agent, portal |
| `discovery.docker.list_containers` | `sockets` | agent, portal |
| `discovery.processes.read` | `methods` (`ps`, `procfs`), `proc_roots` (needed for `procfs`) | agent, portal |
| `discovery.network.tcp_connect` | `cidrs` (requested ranges must be inside them), `ports`, `max_hosts` | agent, portal |
| `llm.propose_ids` | `models`, `api_origins`, `max_calls_per_run`, `send_attributes` (the most that may be sent) | agent, portal |
| `server.connect` | `urls`: which SPIFFE server the agent may talk to | agent, portal |
| `server.entries.list`, `server.entries.delete` | none | agent, portal, **server** |
| `server.entries.create`, `server.svid.x509` | `spiffe_id_prefixes` | agent, portal, **server** |
| `server.svid.jwt` | `spiffe_id_prefixes`, `audiences` | agent, portal, **server** |
| `portal.scan`, `portal.approve`, `portal.revoke` | none | portal |

### Rules

- **Fail closed:**
  - no policy file, an invalid one, or one every user can write to stops the program,
  - `"default"` must be `"deny"`, so there's no allow-all mode.
- **Unlisted means blocked:**
  - a tool missing from the policy is denied, even if the config enables it,
  - a listed tool without its limits, an unknown tool name or an unknown limit is a startup error, so a typo can't silently change access.
- **Enforced twice:**
  - the agent and portal check before they act,
  - the identity server loads its own copy of the policy and refuses server actions it doesn't allow, with HTTP 403, even for a caller holding the admin token.
- **One gate:** every action in the code goes through a single function, `ToolGate.check` / `ToolGate.action`.

### The trace file

One JSON line per event, written by the agent, portal and server to the file named in the policy:

| Event | Meaning |
|---|---|
| `run.start` / `run.end` | a command, portal action or server request began or ended (with status and duration) |
| `action.decision` | the policy allowed or denied an action, with the reason and the values it checked |
| `action.result` | an allowed action finished: `ok` or `error`, duration, and a short summary |
| `log` | an ordinary log message |

- **Linked across processes:** every event carries a `trace_id`. The agent sends its trace id to the server in an `X-Trace-Id` header, so one `apply` or one portal **Approve** shows up as a single trace across the agent (or portal) and the server.
- **Never written:** tokens, keys, CSRs, resume text and workload attribute values. Only the facts the policy was checked against (a folder, a host, a SPIFFE ID, a count) go in.
- **Fail closed:** if the trace can't be written, the action is refused.
- **Not traced:** the server's public read-only endpoints (`/healthz`, `/v1/bundle`, `/v1/bundle/jwks`) and the offline `verify-*` commands. They aren't tools.

To read the trace:

```bash
agent-discovery trace --config examples/demo.config.json
```

```bash
agent-discovery trace --config examples/demo.config.json --denied
```

```bash
agent-discovery trace --config examples/demo.config.json --trace-id cb0001d5
```

Other filters: `--tool server.`, `--component portal`, `--last 50`, and `--json` for raw lines. Every command also prints its `trace id` when it starts, so you can look that run up afterwards.

## Device attestation (Secure Enclave, Phase 1)

Design: [ATTESTATION-MACOS.md](ATTESTATION-MACOS.md). The **server side** is implemented. The **Mac node agent** (Swift, Secure Enclave, Touch ID at enrollment) comes in Phase 2, on a Mac.

- **Devices enroll** with a P-256 public key (admin token) and start **pending**. You approve them in the portal's **Devices** section after comparing the short code.
- **Approved devices get identities** by signing a one-time challenge plus the workload's code-signature evidence. The server issues a **30-minute** SVID only if a registration entry for that device and program matches.
- **New builds:** a new build of an approved program (new cdhash) is held under **New builds awaiting approval** until you approve it.
- **Confidence badges** (High / Medium / Low) come from the `attestation_rubric` in the locked tool policy. Unlisted methods are Low. With no MDM or Apple attestation, nothing is High. Your own client verified through the agent is **Medium**.
- **New tools:** `server.nodes.enroll` (`max_pending`), `server.nodes.list`, `server.nodes.manage`, `server.nodes.challenge`, `server.svid.attested` (`spiffe_id_prefixes`, `max_ttl_minutes`, `require_hardened_runtime`), `portal.devices`, `portal.builds`.

**Trying the server side without a Mac (test only):**
```bash
python scripts/dev_fake_node_agent.py enroll --config examples/demo.config.json --key out/fake-node.pem
```
Approve the device in the portal, add a registration entry for it, then:
```bash
python scripts/dev_fake_node_agent.py svid --config examples/demo.config.json --key out/fake-node.pem --spiffe-id spiffe://demo.local/mac/mcp-client --signing-id com.example.mcp-client --cdhash aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --hardened-runtime --path /usr/local/bin/mcp-client --out out/attested
```
The fake agent uses a **software key on disk**, not the Secure Enclave, and its "evidence" is whatever you type. The portal marks its devices **TEST KEY** in red. Never approve one for anything real.

## Revocation and delegation

Designs: [REVOCATION.md](REVOCATION.md) and [DELEGATION.md](DELEGATION.md).

**Revocation:**
- **Issuance log:** every identity issued is recorded in `issued.jsonl` (never keys). JWTs carry a `jti` so they can be named individually.
- **Revoking:** the admin revokes one identity at a time (portal **Active identities**, or `agent-discovery revoke-svid --serial … | --jti … --reason … --approver …`). Reasons: `key_compromise`, `device_lost`, `superseded`, `decommissioned`, `policy_violation`. The tool policy limits which are allowed.
- **Publishing:** the server publishes a **CA-signed X.509 CRL** (`GET /v1/crl`) and a **signed JWT revocation list** (`GET /v1/revoked-jwt`). Each is valid for `crl_validity_minutes` (5 in the demo).
- **Verifying:** verifiers use `RevocationChecker`, refreshing every 60 seconds and **failing closed**. `verify-x509` and `verify-jwt` require `--server`, a list file, or an explicit `--no-revocation-check`.

**Delegation (human → agent):**
- **Grants:** the admin creates a grant (portal **Delegation grants**, or `agent-discovery grant --principal … --agent … --scope … --minutes … --approver …`). At most 60 minutes in the demo policy.
- **Delegated identities:** an agent asks for an identity under a grant (`--grant`, optionally a `--scope` subset). The identity then carries the person, scopes and end time (JWT `del` claim, or a non-critical X.509 extension), never outlives the grant, and can't widen it.
- **Service identities:** without `--grant`, an agent gets a plain service identity.
- **Limits:** names are typed and **unverified**, and scopes are **recorded, not yet enforced**. The MCP gateway will enforce them.

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
