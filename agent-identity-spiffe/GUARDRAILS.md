# LLM Guardrails: Design Draft (v0.2, for review)

**Scope:** the one place this project talks to an LLM: the optional Claude step that proposes SPIFFE IDs for workloads no policy rule matched (`spiffe_identity/classifier.py`, tool `llm.propose_ids`).
**Status:** draft. Nothing in this document is implemented yet unless it's marked **exists**. Items marked **[OPEN]** are decisions still needed from you; they're collected in [section 9](#9-open-questions).

## 0. Decisions made (v0.2)

| # | Question | Your decision | What it means in the design |
|---|---|---|---|
| D1 | Q1: send the workload name? | **Never send it. Traces must include it.** | IN-1 always strips `name` from what goes to Claude. Every guardrail and LLM trace event records the workload's name, kind and source locally, so you can tell which workload a decision was about. |
| D2 | Q4: what happens when text looks like prompt injection? | **Hold it for human review; a person approves sending it or blocks it.** | IN-5 puts the workload on hold instead of sending it. A reviewer sees the flagged field and chooses *send* or *block* (section 4.1). Nothing on hold is sent without that approval. |
| D3 | Q6: reply from a model the policy didn't allow? | **Throw the reply away, warn the admin, record it in the logs.** | OUT-2 is `block_call`: no proposals from that reply are used. A warning is shown in `plan`, `apply` and the portal, and a trace event records the requested and served models. |
| D4 | Q9: where do guardrail settings live? | **In a locked file.** | The settings go in `tool-policy.json`, the same locked file as the tool policy, under the same fail-closed rules (section 7). |


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
- **G1:** the workload's `name` is **always** sent, even if it isn't in `send_attributes`. Names can carry usernames, hostnames, or injected text (e.g. a crafted MCP server name). → **Decided (D1): never send it.**
- **G2:** the request uses server-side refusal fallbacks (`fallbacks: "default"`), so the reply can come from a different model than the one the tool policy allowed. The served model is traced but not checked. → **Decided (D3): discard such replies, warn and log.**
- **G3:** the reply is only partly validated against `OUTPUT_SCHEMA` locally. For example, `confidence` isn't checked against its allowed values.

## 3. Principles

1. **Fail closed.** If a guardrail can't run, because of an error or bad config, the LLM call doesn't happen and workloads stay unassigned.
2. **Per item where possible.** A problem with one workload removes *that* workload from the call or drops *that* proposal. It doesn't sink the whole batch, unless the problem is batch-wide (see the actions in section 6).
3. **Structure over detection.** Heuristic injection detection can be bypassed. The real defences are structural: JSON framing, schema-constrained output, the grounding check (OUT-5), no tools for the LLM, and human approval. Detection is an extra layer, not the main wall.
4. **Never leak while guarding.** Guardrail traces record *which rule* fired, *which field*, and *which workload* (name, kind, source, per D1), never the offending value. A detected secret must not end up in the trace file.
5. **Explain every block.** Each blocked item gets a human-readable reason that shows up in `plan`, the approval prompt and the portal.

## 4. Input guardrails (before anything is sent)

Applied to each workload, in this order:

| ID | Guardrail | Check | Default action | Status |
|---|---|---|---|---|
| IN-1 | **Field allowlist** | Send only `index`, `kind`, `source` and the keys in `send_attributes` (also capped by the tool policy). The workload `name` is **never** sent (D1). The name is still recorded in the trace. | strip | partly exists (E2); name removal new |
| IN-2 | **Normalise text** | Unicode NFKC. Remove control characters, zero-width characters and bidirectional-override characters, which can hide text from reviewers. | rewrite | new |
| IN-3 | **Secret scan** | Patterns for API keys (`sk-ant-…`, `sk-…`, `AKIA…`, `ghp_…`/`github_pat_…`, `xox[bp]-…`), private-key blocks, JWTs (`eyJ…`), `Bearer …`, `password=`/`token=`/`secret=` pairs, and long high-entropy strings. **[OPEN Q2]** | block item | new |
| IN-4 | **Personal data scan** | Email addresses, phone numbers, home-folder usernames in paths (`/Users/<name>/`, `/home/<name>/`). | redact (`/Users/<user>/`) **[OPEN Q3]** | new |
| IN-5 | **Prompt-injection screen** | Phrases aimed at the model ("ignore previous/above instructions", "you are now", "system:", "assistant:"); fake delimiters such as `</workloads>`, triple-backtick fences or role tags; instructions to output a specific SPIFFE ID. | **hold for human review** (D2, section 4.1) | new |
| IN-6 | **Size limits** | Max characters per value, max attributes per workload, max workloads per call, max total payload bytes. **[OPEN Q5]** | value: truncate with a marker; batch: split or block call | new |
| IN-7 | **Policy gate** | `llm.propose_ids` allowed: model, API origin, call budget, attribute ceiling. | block call | exists (E1) |

A workload blocked on input is never sent. It stays **Unassigned** with a reason such as `"not sent to the LLM: secret-like value in attribute 'command' (rule IN-3)"`. Nothing is guessed for it.

**What D1 changes for Claude.** Without the name, Claude only sees `kind`, `source` and the attributes you allow. For AI agents and MCP servers, the name usually also exists as an attribute (`agent_name`, `server_name`). If you want Claude to use it, list that attribute in `send_attributes`. It then goes through the same screening (IN-2 to IN-6) as any other value. If it isn't listed, Claude can't use the name, and OUT-5 rejects any path segment that only the name could have supplied.

### 4.1 Human review of held workloads (D2)

When IN-5 flags a workload, the workload goes on **hold**:

1. **Nothing is sent yet.** The held workload is left out of the LLM call. Other workloads continue.
2. **The reviewer sees what was flagged:**
   - the workload's name, kind and source,
   - which field matched which pattern,
   - the flagged text itself, shown **locally** only (CLI or portal), never sent anywhere. Any secrets in it are still masked by IN-3.
3. **The reviewer decides:**
   - **Send:** the workload goes to Claude in a follow-up call, still through every other guardrail.
   - **Block:** it stays unassigned with the reason `"blocked by <reviewer> after injection review"`.
4. **Where reviews happen:**
   - `apply` asks for each held workload before the LLM call,
   - the portal shows a **Held for review** list with Send and Block buttons,
   - `plan`, which is read-only, only lists held workloads.
5. **Recorded:** every hold, and every send or block decision, is a trace event with the workload name, rule, field, decision and reviewer. The flagged text isn't stored in the trace.
6. **Fail closed:** if nobody reviews (non-interactive run, portal closed), held workloads are **not sent**. Whether `--approve-all` should be allowed to approve holds is an open question (Q11).

## 5. Output guardrails (before a proposal is shown or approved)

Applied to the reply as a whole, then to each proposal:

| ID | Guardrail | Check | Default action | Status |
|---|---|---|---|---|
| OUT-1 | **Stop reason** | `refusal` or `max_tokens` means no proposals. | block call | exists (E6) |
| OUT-2 | **Served model** | `response.model` must be in the tool policy's `models` (catches a fallback to an unapproved model, G2). | **block call + admin warning + trace event** (D3, below) | new |
| OUT-3 | **Strict schema** | Validate the parsed JSON locally against `OUTPUT_SCHEMA`: types, required fields, `confidence` values, no extra fields. | block call if the top level is invalid; drop the item if one item is invalid | partly exists |
| OUT-4 | **Index integrity** | Each index is in range and appears once. A missing answer is reported as such. | drop item | exists (E7) |
| OUT-5 | **Grounding (anti-invention)** | Every path segment must come from the workload's *sent* data (an attribute value, `kind`, or `name` if sent; compared after the same sanitising the policy rules use) **or** from a small fixed role vocabulary (`ai-agent`, `mcp`, `stdio`, `http`, `k8s`, `ns`, `sa`, `container`, `process`, `agent`). A segment with no source is invented. **[OPEN Q7]** | drop item | new |
| OUT-6 | **Naming policy** | The path prefix fits the workload's kind (e.g. an `mcp-server` must start `/mcp/`) and falls within the tool policy's `server.entries.create` prefixes, so you're never asked to approve something that can't be registered. | drop item | new |
| OUT-7 | **Specificity and collisions** | Reject IDs that are too generic (a single segment, or only role words like `/agent`). Reject two different workloads given the same ID in one reply. Flag an ID that's already registered to different selectors. | drop item (generic or duplicate); flag (already registered) | new |
| OUT-8 | **SPIFFE validity** | A valid ID in the configured trust domain. | drop item | exists (E8) |
| OUT-9 | **Rationale hygiene** | Cap the length. Strip control characters and markup. The rationale must name at least one attribute that was actually sent; otherwise flag it as "rationale not grounded". | rewrite and flag | new |
| OUT-10 | **Low confidence** | `confidence: low`. | flag **[OPEN Q8]** | new |
| OUT-11 | **Human approval** | Every surviving proposal, with its guardrail flags, is approved or rejected by a person. | — | exists (E9) |

**OUT-2 details (D3).** When the served model isn't allowed:
- **The reply is discarded.** None of its proposals are used, and every workload in that call stays unassigned with the reason `"LLM reply discarded: served by <model>, which the tool policy doesn't allow"`.
- **The admin is warned:**
  - `plan` and `apply` print a warning to the terminal,
  - the portal shows a red banner on the scan result,
  - the scan snapshot keeps the warning, so it's still visible after a reload.
- **It's logged:** a trace event `guardrail.check` with `rule: OUT-2`, the requested model, the served model and the token counts. A discarded reply was still billed, so the cost stays visible.

**Flags** don't block. They're shown next to the proposal in `plan`, in the `apply` prompt and in the portal (e.g. *"⚠ LLM proposal: low confidence; rationale doesn't cite a sent attribute"*), so the reviewer has the context.

## 6. Actions

| Action | Meaning |
|---|---|
| `allow` | passes unchanged |
| `rewrite` | value changed in a safe, logged way (normalised, truncated, redacted) |
| `flag` | passes, with a visible warning to the human reviewer |
| `block_item` | this workload isn't sent, or this proposal is dropped; others continue |
| `hold_for_review` | this workload isn't sent until a person reviews the flagged field and chooses *send* or *block* (section 4.1); others continue |
| `block_call` | the whole LLM call is cancelled or its reply discarded; all workloads stay unassigned |

## 7. Configuration, tracing and testing

**Configuration (D4).** Guardrail settings are security controls, so they live in the locked tool policy file, not the everyday config. New section in `tool-policy.json`:

```json
"guardrails": {
  "llm.propose_ids": {
    "secret_scan": "block_item",
    "pii": "redact",
    "injection_screen": "hold_for_review",
    "limits": {"value_chars": 256, "attributes_per_workload": 10, "workloads_per_call": 20, "payload_bytes": 32768},
    "served_model": "block_call",
    "low_confidence": "flag",
    "role_vocabulary": ["ai-agent", "mcp", "stdio", "http", "k8s", "ns", "sa", "container", "process", "agent"]
  }
}
```

There's no `send_name` setting: per D1, the name is never sent, and that isn't configurable. `served_model` is fixed to discarding the reply (D3) and isn't configurable either. Both are hard-coded so the locked file can't loosen them.

"Locked" means the same fail-closed rules as the tool policy:
- a missing, invalid or world-writable file stops the program,
- unknown keys, missing keys or invalid actions are startup errors,
- there are no silent defaults.

Whether to also refuse a file that's writable by the user's group is open (Q12).

**Tracing.** Every guardrail decision becomes a trace event:

```json
{"event": "guardrail.check", "rule": "IN-3", "side": "input", "action": "block_item",
 "workload": {"name": "filesystem", "kind": "mcp-server", "source": "ai-agents"},
 "field": "command", "detail": "anthropic-key-like value"}
```

It records the rule, the field, the kind of match and the workload's name, kind and source (D1), never the matched value. Review decisions (D2) add `"decision": "send" | "block"` and `"reviewer"`. `agent-discovery trace --tool guardrail` would filter them.

**Testing** (offline, no API calls):
- **Rule tests:** one test per rule, with adversarial fixtures, e.g. injection strings, fake keys such as `sk-ant-EXAMPLE…`, zero-width and bidi tricks.
- **Name never sent:** the request payload never contains a workload name, while the trace does.
- **Hold workflow:** held workloads aren't sent without approval, "send" includes them in a follow-up call, "block" leaves them unassigned, and non-interactive runs send nothing that's on hold.
- **Known-bad outputs:** a fake Claude client returns invented segments, wrong prefixes, duplicate IDs, an unapproved model, bad schema, or a long rationale with markup. Each must be caught by the right rule.
- **False positives:** run the input guardrails over the demo fixtures and the laptop scan, and confirm normal workloads aren't blocked.
- **Fail closed:** an exception inside a guardrail means no LLM call happens.

**Not in v1:**
- an ML or LLM-based injection classifier,
- an LLM-as-judge inside the request path (cost; it fits better in `agent-evaluator/`),
- guardrails for the other agents in the repo.

## 8. Answered questions

- **Q1 (send the name?):** see D1.
- **Q4 (injection hits?):** see D2.
- **Q6 (fallback model?):** see D3.
- **Q9 (where settings live?):** see D4.

## 9. Open questions

Still open from v0.1:

2. **Q2: Secret patterns.** Is the list in IN-3 enough? Are there other credential formats in your environment, e.g. internal tokens?
3. **Q3: Personal data.** Redact (send `/Users/<user>/…`) or block the workload entirely?
5. **Q5: Size limits.** Are the numbers in the config example acceptable starting values? They're placeholders for you to set, not recommendations.
7. **Q7: Role vocabulary.** Which fixed words may appear in a path without coming from the workload's data? The list in section 7 mirrors your current policy rules.
8. **Q8: Low confidence.** Flag only, or drop low-confidence proposals?

New, from your decisions:

10. **Q10: Remember review decisions?** If you send or block a held workload, should that decision be remembered for the same workload with the same flagged text, so the next scan doesn't ask again? Or ask every scan? If the text changes, it would always be asked again.
11. **Q11: `--approve-all` and holds.** Should `--approve-all` (demo and test only) also approve sending held workloads, or must holds always be decided by a person one at a time? I'd lean towards always by a person.
12. **Q12: How locked is "locked"?** Today the policy file is refused only if *every* user can write to it. Should it also be refused if the user's *group* can write to it? Should the config optionally pin the policy's SHA-256 hash, so any edit stops the agent until you update the pin?
13. **Q13: Fallbacks.** With D3 in place, a fallback reply from an unapproved model is billed and then thrown away. Should fallbacks be turned off for this step, so that doesn't happen? Or keep them, in case the fallback model is one you add to the policy later?
