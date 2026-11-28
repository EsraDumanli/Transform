# Delegation (Human → Agent): Design (v0.2; implemented)

**Goal:** every issued identity can say **which person the agent is acting for**, **what it may do for them**, and **until when**, and the dashboard shows it. This addresses the "on whose behalf?" gap from the OWASP agentic review (ASI03, Identity & Privilege Abuse).

**Status:** **implemented** on `SPIFFE-Changes`: grants (create, list, withdraw), delegated X.509 and JWT identities, the issuance log showing delegation, CLI and portal. Scopes are recorded, not yet enforced (MCP gateway).

## 0. Decisions made

| # | Question | Decision |
|---|---|---|
| G1 | What kind of delegation | **Human → agent:** the person an agent acts on behalf of. |
| G2 | Where it's recorded | **On each issued identity:** each 30–60 minute identity carries the delegation it was issued under, so it can differ per session. |
| G3 | What's recorded | **Who + scope + expiry:** the person, the scopes they delegated (e.g. tools or data), and an end time. Shown now; enforced later by the MCP gateway. |
| G4 | How a person is identified | **A typed name**, like today's `--approver`. **Not verified** (see section 5). |
| G5 | Q1: must agent identities be delegated? | **No:** agents can also get service identities. |
| G6 | Q2: scope types and limits | **`tool:`, `data:path:`, `data:host:`**; longest grant **60 minutes** (`max_grant_minutes: 60`). |
| G7 | Q4: claim format | **Custom `del` claim**; `sub` stays the agent. |
| G8 | Q5: build order | **Issuance log first**, then revocation and delegation. |

## 1. The core rule: an agent can't claim a person by itself

If agents could write "acting for Esra" into their own identity request, any agent could claim anyone. So delegation works in two steps:

1. **A person creates a delegation grant** in the portal or CLI (admin only, traced): *"Esra delegates to `spiffe://demo.local/mac/mcp-client` the scopes `tool:filesystem.read_file` and `data:path:~/Projects/transform/**` until 2026-12-05 18:00."*
2. **The agent asks for an identity and names the grant ID.** The server issues a delegated identity **only if** the grant:
   - exists and is active (not expired, not withdrawn),
   - is for **exactly this SPIFFE ID**,
   - allows the scopes requested. The agent may ask for fewer scopes than the grant, never more.

Every issued identity then carries the grant's person, scopes and end time, and the identity can't outlive the grant (section 3).

## 2. Delegation grant (new record)

| Field | Example | Notes |
|---|---|---|
| `id` | `g_7c21…` | random |
| `principal` | `Esra` | typed name (G4), **unverified** |
| `agent_spiffe_id` | `spiffe://demo.local/mac/mcp-client` | must have a registration entry |
| `scopes` | `["tool:filesystem.read_file", "data:path:~/Projects/transform/**"]` | format `<type>:<value>` (section 4) |
| `not_before`, `not_after` | `2026-11-28T10:00Z` … `2026-12-05T18:00Z` | `not_after` is required: there's no "forever" grant |
| `created_by`, `created_at` | `Esra`, … | who entered it, from the portal's approver name |
| `status` | `active` / `withdrawn` / `expired` | withdrawing stops **new** delegated identities |
| `note` | "Read-only access for the triage project" | optional, max 200 characters |

Stored in `<data_dir>/grants.json` (mode 0600). Every change is a trace event.

## 3. What a delegated identity carries

**JWT-SVID.** The SPIFFE standard requires `sub` to be the agent's SPIFFE ID, so delegation goes in its own claim rather than replacing `sub`:

```json
{"sub": "spiffe://demo.local/mac/mcp-client", "aud": ["ticket-api"], "exp": 1764351000, "jti": "…",
 "del": {"principal": "Esra", "principal_verified": false, "grant": "g_7c21…",
         "scopes": ["tool:filesystem.read_file"], "until": 1764957600}}
```

- The claim name `del` and its shape are **[OPEN Q4]**. One alternative is the standard token-exchange `act` claim (RFC 8693), but that puts the *person* in `sub`, which conflicts with the SPIFFE rule.

**X.509-SVID.** The same data goes in a **non-critical certificate extension** with a private identifier. Verifiers that don't understand it ignore it, so ordinary TLS still works. The certificate's identity, the URI SAN, is unchanged.

**Expiry rule:** an identity's lifetime is the **shorter** of its normal lifetime (30 minutes attested, 60 otherwise) and the time left on the grant. A delegated identity never outlives its delegation.

**The issuance log** records the delegation on every identity: principal, grant, scopes, until. This is the same issuance log the revocation design needs, so it would be built once for both.

## 4. Scopes

- **Format:** `<type>:<value>`. Proposed types:
  - `tool:<server>.<tool>`, e.g. `tool:filesystem.read_file`,
  - `data:path:<glob>`, e.g. `data:path:~/Projects/transform/**`,
  - `data:host:<hostname>`, e.g. `data:host:api.example.com`.
- **v1 records and displays scopes but doesn't enforce them.** Enforcement comes with the MCP gateway, which will check each tool call against the scopes in the caller's identity. The dashboard says "recorded, not yet enforced" so nobody mistakes it for protection.
- **The locked tool policy caps what grants may contain:**
  - `allowed_scope_types`, e.g. only `tool` and `data:path`,
  - `max_grant_days`, the longest grant allowed.

  A grant outside those limits is refused. **[OPEN Q2]**

## 5. Honesty about typed names (G4)

- **The principal name is whatever the admin typed.** The system doesn't check it, so any admin could type any name.
- **What it gives you:** a record of *what the admin declared*, with `created_by` and the trace showing who entered it and when. It isn't proof of the person's consent.
- **How it's shown:**
  - the dashboard displays the name with an **"unverified name"** marker,
  - identities carry `principal_verified: false`, so a future verifier can't mistake it for a checked identity.
- **Upgrade path:** a verified login (SSO/OIDC) can replace the typed name later. The record already has the `principal_verified` field for it.

## 6. Dashboard

- **New section, Delegation grants:**
  - columns: person (with the "unverified" marker), agent identity, scopes, valid from → until, created by, status,
  - actions: **New grant** (pick an agent from registered entries, type the person, choose scopes, pick an end time) and **Withdraw**.
- **New section, Active identities** (shared with the revocation design): each unexpired issued identity shows **"acts for Esra · 2 scopes · until 18:00"**, or **"no delegation (service identity)"**.
- **Identity details:** clicking an identity shows its grant, the scope list, and the trace link.

## 7. Policy, issuance and trace changes

- **New tools in the locked policy:**
  - `server.grants.create`: limits `max_grant_days`, `allowed_scope_types`,
  - `server.grants.list`,
  - `server.grants.withdraw`,
  - `portal.grants`.
- **Issuance:**
  - the attested request (`/v1/node/svid`) and the admin issuance endpoints accept an optional `delegation: {"grant": "<id>", "scopes": [...]}`,
  - with no delegation, the identity is issued as a **service identity**, unless the policy requires delegation for that SPIFFE ID prefix. **[OPEN Q1]**
- **Trace:** grant created, withdrawn or expired; delegated issuance (principal, grant, scopes); and refusals (unknown grant, wrong agent, scope not in grant, grant expired).

## 8. Not in scope (v1)

- Agent → agent delegation chains (G1 limits this to human → agent).
- Enforcing scopes on tool calls: that's the MCP gateway.
- Verified identities for people (SSO/OIDC).
- Revoking identities already issued under a withdrawn grant. They expire on their own, within 30–60 minutes and never after the grant's end. Automatic revocation is **[OPEN Q3]** and depends on the revocation design.

## 9. Open questions

1. **Q1: Must agent identities be delegated?** Should some SPIFFE ID prefixes (e.g. `/mac/`) **require** a delegation grant, or may agents always also get plain service identities?
2. **Q2: Scope types and limits.** Are `tool:`, `data:path:` and `data:host:` the right starting types? What's the longest grant you'd allow (`max_grant_days`)?
3. **Q3: Withdrawing a grant.** Should withdrawing also revoke the identities already issued under it, once revocation is built? Or let them expire (at most 30–60 minutes)?
4. **Q4: Claim format.** Is a custom `del` claim OK, keeping `sub` = the agent as SPIFFE requires? The alternative is closer to the token-exchange standard, but conflicts with SPIFFE.
5. **Q5: Build order.** Delegation and revocation both need the same **issuance log**. I suggest building the issuance log first, then revocation and delegation on top. OK?
