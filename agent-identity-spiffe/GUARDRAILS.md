# LLM Guardrails: Design Draft (v0.1, for review)

**Scope:** the one place this project talks to an LLM: the optional Claude step that proposes SPIFFE IDs for workloads no policy rule matched (`spiffe_identity/classifier.py`, tool `llm.propose_ids`).
**Status:** draft. Nothing in this document is implemented yet unless it's marked **exists**. Items marked **[OPEN]** are decisions for you; they're collected in [section 8](#8-open-questions).

## 1. Why guardrails here

The Claude step sits between two untrusted sides:

```
 discovered workloads ──► INPUT GUARDRAILS ──► Claude ──► OUTPUT GUARDRAILS ──► proposal ──► human approval ──► registration
 (manifests, labels,       what may leave       (untrusted   what may come back                (exists)
  process names: untrusted) the machine          output)      and become an identity
```

- **Input risks:**
  - leaking secrets or personal data to the API (a token on a command line, a username in a path),
  - prompt injection hidden in a manifest, label or agent card,
  - oversized payloads that cost money or truncate the answer.
- **Output risks:**
  - an invented identity, where a path segment isn't backed by any observed fact,
  - an identity that breaks the naming policy, is over-broad, or collides with another workload's,
  - malformed output,
  - an answer from a model you didn't approve.

A wrong identity grants the wrong access, so the output side matters as much as the input side.

## 2. What already exists

| # | Control | Where | Side |
|---|---|---|---|
| E1 | LLM step is off by default (`llm.enabled`) and must be allowed by the tool policy (`llm.propose_ids`: models, API origins, call budget, attribute ceiling) | config, `toolpolicy.py` | input |
| E2 | Attribute allowlist: only keys in `llm.send_attributes` are sent | `classifier.py` `_payload` | input |
| E3 | System prompt frames workload values as untrusted data and prefers "insufficient data" over guessing | `classifier.py` `SYSTEM_PROMPT` | input |
| E4 | Values sent as JSON (`json.dumps`), never pasted into the prompt as prose | `classifier.py` | input |
| E5 | Structured output: a JSON schema is requested (`output_config.format`) | `classifier.py` `OUTPUT_SCHEMA` | output |
| E6 | Stop reasons: `refusal` and `max_tokens` become errors; workloads stay unassigned | `classifier.py` `_apply` | output |
| E7 | Index checks: out-of-range or duplicate indexes are ignored | `_apply` | output |
| E8 | Every proposed path is re-validated as a SPIFFE ID in the configured trust domain | `_apply` | output |
| E9 | LLM proposals are labelled `llm:<model>` and still need human approval | `approval.py`, portal | output |
| E10 | Every call is traced: decision, model served, stop reason, token counts | `toolpolicy.py`, `trace.py` | both |

**Gaps found while writing this draft:**
- **G1:** the workload's `name` is **always** sent, even if it isn't in `send_attributes`. Names can carry usernames, hostnames, or injected text (e.g. a crafted MCP server name). **[OPEN Q1]**
- **G2:** the request uses server-side refusal fallbacks (`fallbacks: "default"`), so the reply can come from a different model than the one the tool policy allowed. The served model is traced but not checked. **[OPEN Q6]**
- **G3:** the reply is only partly validated against `OUTPUT_SCHEMA` locally. For example, `confidence` isn't checked against its allowed values.

## 3. Principles

1. **Fail closed.** If a guardrail can't run, because of an error or bad config, the LLM call doesn't happen and workloads stay unassigned.
2. **Per item where possible.** A problem with one workload removes *that* workload from the call or drops *that* proposal. It doesn't sink the whole batch, unless the problem is batch-wide (see the actions in section 6).
3. **Structure over detection.** Heuristic injection detection can be bypassed. The real defences are structural: JSON framing, schema-constrained output, the grounding check (OUT-5), no tools for the LLM, and human approval. Detection is an extra layer, not the main wall.
4. **Never leak while guarding.** Guardrail traces record *which rule* fired and *which field*, never the offending value. A detected secret must not end up in the trace file.
5. **Explain every block.** Each blocked item gets a human-readable reason that shows up in `plan`, the approval prompt and the portal.

## 4. Input guardrails (before anything is sent)

Applied to each workload, in this order:

| ID | Guardrail | Check | Default action | Status |
|---|---|---|---|---|
| IN-1 | **Field allowlist** | Send only `index`, `kind`, `source` and the keys in `send_attributes` (also capped by the tool policy). Whether `name` is sent becomes a choice (G1). | strip | partly exists (E2) |
| IN-2 | **Normalise text** | Unicode NFKC. Remove control characters, zero-width characters and bidirectional-override characters, which can hide text from reviewers. | rewrite | new |
| IN-3 | **Secret scan** | Patterns for API keys (`sk-ant-…`, `sk-…`, `AKIA…`, `ghp_…`/`github_pat_…`, `xox[bp]-…`), private-key blocks, JWTs (`eyJ…`), `Bearer …`, `password=`/`token=`/`secret=` pairs, and long high-entropy strings. **[OPEN Q2]** | block item | new |
| IN-4 | **Personal data scan** | Email addresses, phone numbers, home-folder usernames in paths (`/Users/<name>/`, `/home/<name>/`). | redact (`/Users/<user>/`) **[OPEN Q3]** | new |
| IN-5 | **Prompt-injection screen** | Phrases aimed at the model ("ignore previous/above instructions", "you are now", "system:", "assistant:"); fake delimiters such as `</workloads>`, triple-backtick fences or role tags; instructions to output a specific SPIFFE ID. | block item **[OPEN Q4]** | new |
| IN-6 | **Size limits** | Max characters per value, max attributes per workload, max workloads per call, max total payload bytes. **[OPEN Q5]** | value: truncate with a marker; batch: split or block call | new |
| IN-7 | **Policy gate** | `llm.propose_ids` allowed: model, API origin, call budget, attribute ceiling. | block call | exists (E1) |

A workload blocked on input is never sent. It stays **Unassigned** with a reason such as `"not sent to the LLM: secret-like value in attribute 'command' (rule IN-3)"`. Nothing is guessed for it.

## 5. Output guardrails (before a proposal is shown or approved)

Applied to the reply as a whole, then to each proposal:

| ID | Guardrail | Check | Default action | Status |
|---|---|---|---|---|
| OUT-1 | **Stop reason** | `refusal` or `max_tokens` means no proposals. | block call | exists (E6) |
| OUT-2 | **Served model** | `response.model` must be in the tool policy's `models` (catches a fallback to an unapproved model, G2). | block call or flag **[OPEN Q6]** | new |
| OUT-3 | **Strict schema** | Validate the parsed JSON locally against `OUTPUT_SCHEMA`: types, required fields, `confidence` values, no extra fields. | block call if the top level is invalid; drop the item if one item is invalid | partly exists |
| OUT-4 | **Index integrity** | Each index is in range and appears once. A missing answer is reported as such. | drop item | exists (E7) |
| OUT-5 | **Grounding (anti-invention)** | Every path segment must come from the workload's *sent* data (an attribute value, `kind`, or `name` if sent; compared after the same sanitising the policy rules use) **or** from a small fixed role vocabulary (`ai-agent`, `mcp`, `stdio`, `http`, `k8s`, `ns`, `sa`, `container`, `process`, `agent`). A segment with no source is invented. **[OPEN Q7]** | drop item | new |
| OUT-6 | **Naming policy** | The path prefix fits the workload's kind (e.g. an `mcp-server` must start `/mcp/`) and falls within the tool policy's `server.entries.create` prefixes, so you're never asked to approve something that can't be registered. | drop item | new |
| OUT-7 | **Specificity and collisions** | Reject IDs that are too generic (a single segment, or only role words like `/agent`). Reject two different workloads given the same ID in one reply. Flag an ID that's already registered to different selectors. | drop item (generic or duplicate); flag (already registered) | new |
| OUT-8 | **SPIFFE validity** | A valid ID in the configured trust domain. | drop item | exists (E8) |
| OUT-9 | **Rationale hygiene** | Cap the length. Strip control characters and markup. The rationale must name at least one attribute that was actually sent; otherwise flag it as "rationale not grounded". | rewrite and flag | new |
| OUT-10 | **Low confidence** | `confidence: low`. | flag **[OPEN Q8]** | new |
| OUT-11 | **Human approval** | Every surviving proposal, with its guardrail flags, is approved or rejected by a person. | — | exists (E9) |

**Flags** don't block. They're shown next to the proposal in `plan`, in the `apply` prompt and in the portal (e.g. *"⚠ LLM proposal: low confidence; rationale doesn't cite a sent attribute"*), so the reviewer has the context.

## 6. Actions

| Action | Meaning |
|---|---|
| `allow` | passes unchanged |
| `rewrite` | value changed in a safe, logged way (normalised, truncated, redacted) |
| `flag` | passes, with a visible warning to the human reviewer |
| `block_item` | this workload isn't sent, or this proposal is dropped; others continue |
| `block_call` | the whole LLM call is cancelled or its reply discarded; all workloads stay unassigned |

## 7. Configuration, tracing and testing

**Configuration.** Guardrail settings are security controls, so they belong with the tool policy, in a locked file, not the everyday config. Proposed new section in `tool-policy.json`: **[OPEN Q9]**

```json
"guardrails": {
  "llm.propose_ids": {
    "send_name": false,
    "secret_scan": "block_item",
    "pii": "redact",
    "injection_screen": "block_item",
    "limits": {"value_chars": 256, "attributes_per_workload": 10, "workloads_per_call": 20, "payload_bytes": 32768},
    "served_model": "block_call",
    "low_confidence": "flag",
    "role_vocabulary": ["ai-agent", "mcp", "stdio", "http", "k8s", "ns", "sa", "container", "process", "agent"]
  }
}
```

The same strict rules as the rest of the policy apply: unknown keys, missing keys or invalid actions are startup errors, and there are no silent defaults.

**Tracing.** Every guardrail decision becomes a trace event:

```json
{"event": "guardrail.check", "rule": "IN-3", "side": "input", "action": "block_item",
 "workload_index": 2, "field": "command", "detail": "anthropic-key-like value"}
```

It records the rule, field and kind of match, never the matched value. `agent-discovery trace --tool guardrail` would filter them.

**Testing** (offline, no API calls):
- **Rule tests:** one test per rule, with adversarial fixtures, e.g. injection strings, fake keys such as `sk-ant-EXAMPLE…`, zero-width and bidi tricks.
- **Known-bad outputs:** a fake Claude client returns invented segments, wrong prefixes, duplicate IDs, an unapproved model, bad schema, or a long rationale with markup. Each must be caught by the right rule.
- **False positives:** run the input guardrails over the demo fixtures and the laptop scan, and confirm normal workloads aren't blocked.
- **Fail closed:** an exception inside a guardrail means no LLM call happens.

**Not in v1:**
- an ML or LLM-based injection classifier,
- an LLM-as-judge inside the request path (cost; it fits better in `agent-evaluator/`),
- guardrails for the other agents in the repo.

## 8. Open questions

1. **Q1: Send the workload name?** Today it's always sent (G1). Options:
   - (a) never,
   - (b) only if listed in `send_attributes`,
   - (c) always, but through IN-2 to IN-5 like any other value.

   I'd lean towards (b).
2. **Q2: Secret patterns.** Is the list in IN-3 enough? Are there other credential formats in your environment, e.g. internal tokens?
3. **Q3: Personal data.** Redact (send `/Users/<user>/…`) or block the workload entirely?
4. **Q4: Injection hits.** Block the workload (safer, may over-block an MCP server whose description says "ignore…"), or send it flagged and rely on the structural defences?
5. **Q5: Size limits.** Are the numbers in the config example acceptable starting values? They're placeholders for you to set, not recommendations.
6. **Q6: Fallback model.** If a refusal fallback answers with a model not in your policy, should the reply be discarded (`block_call`) or kept with a flag? Or should fallbacks be turned off for this step altogether?
7. **Q7: Role vocabulary.** Which fixed words may appear in a path without coming from the workload's data? The list above mirrors your current policy rules.
8. **Q8: Low confidence.** Flag only, or drop low-confidence proposals?
9. **Q9: Where the settings live.** Inside `tool-policy.json` (locked, reviewed with the policy), as proposed, or in the regular config?
