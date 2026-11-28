# Identity Revocation: Design Draft (v0.1, for review)

**Problem:** today, deleting a registration entry or revoking a device only stops **new** identities. An identity (SVID) that was already issued keeps working until it expires: up to **30 minutes** for attested identities and **60 minutes** for the others in the demo config. If an identity leaks, there's no way to cut it off sooner.

**Status:** design only, nothing built. Items marked **[OPEN]** need your decision ([section 9](#9-open-questions)).

## 0. Decisions made

| # | Question | Decision |
|---|---|---|
| R1 | How revocation reaches verifiers | **Signed revocation list.** The server publishes a CA-signed X.509 CRL for certificates, plus a signed list of revoked JWT IDs. Verifiers download them on a schedule. |
| R2 | What can be revoked | **One issued identity at a time:** a single certificate (by serial number) or a single JWT (by its ID). |
| R3 | When a verifier can't get a fresh list | **Fail closed:** once the list is past its expiry time, verifiers reject every identity until a fresh list arrives. |
| R4 | Who can revoke | **The admin, through the portal or CLI, with a reason from a fixed list.** It's controlled by a new tool in the locked policy, and every revocation is traced. |

## 1. How it works

```
 issue ──► issuance log (serial / JWT id, SPIFFE ID, entry, device, expiry; never keys)
                 │
 admin revokes ──┤ (portal / CLI, reason required, tool policy, traced)
                 ▼
         revocation store ──► signed CRL  (GET /v1/crl)          ──► verifiers refresh every R minutes
                          └─► signed JWT revocation list          ──► reject listed identities
                              (GET /v1/revoked-jwt)                    reject everything if the list expired
```

1. **Every identity is recorded when it's issued**, in a new issuance log. You can't revoke what you can't find.
2. **The admin picks one identity** in the portal's new **Active identities** list, or by serial number in the CLI, chooses a reason, and confirms.
3. **The server adds it to the revocation store** and immediately publishes new signed lists.
4. **Verifiers refresh the lists on a schedule** and reject anything listed. If their copy expires and they can't fetch a new one, they reject *everything* (R3).

## 2. Issuance log (new)

Every certificate and JWT the server issues gets one record. The log is append-only, at `<data_dir>/issued.jsonl`:

| Field | Example | Why |
|---|---|---|
| `kind` | `x509` / `jwt` | what kind of identity |
| `serial` / `jti` | `4f1c…` / `a91b…` | what the revocation list names |
| `spiffe_id` | `spiffe://demo.local/mac/mcp-client` | shown to the admin |
| `entry_id`, `node_id` | `6a39…`, `9151…` | which entry and device it came from |
| `method`, `confidence` | `macos-se-node+codesign`, `medium` | context for the decision |
| `issued_at`, `expires_at` | — | only unexpired identities are revocable |
| `trace_id` | — | link to the trace |

- **Never recorded:** private keys, CSRs, or the certificate or JWT itself.
- **JWT change:** JWT-SVIDs get a random `jti` (JWT ID) claim. Today they don't have one, so they can't be named individually.

## 3. Revoking

| Item | Design |
|---|---|
| **Reasons (fixed list)** | `key_compromise`, `device_lost`, `superseded`, `decommissioned`, `policy_violation`. Each maps to a standard CRL reason code: key compromise (1) for the first two, superseded (4), cessation of operation (5), privilege withdrawn (9). **[OPEN Q2]** |
| **Record** | serial or JWT ID, reason, optional note (max 200 characters, no secrets), `revoked_by`, `revoked_at`, `expires_at` copied from the issuance log |
| **Rules** | Only **unexpired** identities can be revoked. Revoking twice is harmless (it returns the existing record). Revocation can't be undone; issue a new identity instead. |
| **Policy (locked file)** | New tools: `server.svid.list_issued` (no limits); `server.svid.revoke` with a required limit `reasons` (which reasons are allowed); `portal.revoke_identity`. Unlisted means denied, as for every other tool. |
| **Where** | Portal: an **Active identities** list with a **Revoke** button, a reason dropdown and a confirmation. CLI: `agent-discovery revoke-svid --serial <hex> --reason key_compromise [--note "..."]` (or `--jti`). |
| **Trace** | `server.svid.revoke` decision and result, with serial or JWT ID, SPIFFE ID, reason and who. Denied attempts are traced as usual. |

## 4. Publishing the lists

| Endpoint | Content | Signed by |
|---|---|---|
| `GET /v1/crl` | Standard X.509 CRL (DER): revoked serials, reason codes, `thisUpdate`, `nextUpdate`, an increasing CRL number | the CA's key, so verifiers check it with the trust bundle they already have |
| `GET /v1/revoked-jwt` | JWS: `{"jtis": [{"jti": "...", "exp": ...}], "issued_at": ..., "next_update": ..., "number": N}` | the CA's JWT key (`kid` from the JWKS) |

- **Public, like the trust bundle:** these endpoints aren't tools and need no token. The lists contain no secrets: serials, JWT IDs and expiry times only.
- **When they're rebuilt:** immediately after each revocation, and on a timer before `nextUpdate`, so the lists never expire while the server is running.
- **Pruning:** an identity is removed from the list once its own expiry has passed. It's no longer valid anyway, so the lists stay small.

## 5. Verifying

- **A new helper, `RevocationChecker`**, is a small library function for verifiers: your MCP servers, the future gateway, the `verify-*` commands.
  - It fetches both lists every **R** minutes,
  - verifies their signatures against the trust bundle,
  - keeps the newest copy in memory, never going backwards in CRL number,
  - and answers *revoked / not revoked / can't tell*.
- **Fail closed (R3):** if the newest copy is past its `nextUpdate`, or no copy was ever fetched, the answer is *can't tell*, and the identity is **rejected** with a clear error ("revocation list expired at …; refusing identities until a fresh list is available").
- **CLI:** `verify-x509` and `verify-jwt` gain `--crl` / `--revoked-jwt` (a file) or `--server` (fetch live), and they fail closed the same way.

**Timing: two numbers decide how fast revocation works and how much outage you tolerate:**
- **Refresh interval R:** how often verifiers fetch. **A revoked identity can be accepted for at most R** after revocation, plus clock differences.
- **List validity V** (`nextUpdate − thisUpdate`): how long a copy stays usable. Verifiers keep working through a server outage of up to about **V − R**. After that they refuse everything.
- **[OPEN Q1]:** choose R and V, e.g. R = 2 min, V = 10 min (revocation takes effect within 2 minutes; about 8 minutes of outage tolerance). These are placeholders for you to set, not recommendations.

## 6. What changes for existing buttons

Today the portal's **Revoke** on a registration entry and **Revoke** on a device only stop *new* issuance. Since R2 limits revocation to individual identities, with no automatic cascades:
- **Rename** the entry button to **Delete entry**, so "revoke" only ever means revoking an identity. The device action stays "Revoke device", with clearer text.
- **After either action, the portal says what's still active**, e.g. "3 identities issued from this entry are still valid until 14:32. Revoke them individually in Active identities if needed." That makes the remaining exposure visible rather than surprising.
- **Should these cascade automatically?** Not under R2. **[OPEN Q3]**

## 7. Testing

- **Issuance log:** every issuance creates a record with the right serial or JWT ID, and no key material is ever written.
- **Revoking:** only the admin can revoke; reasons not allowed by the policy are denied; an expired identity can't be revoked; revoking twice is harmless.
- **The CRL:** it parses as a standard X.509 CRL, its signature verifies with the bundle, it lists exactly the unexpired revoked serials with the right reason codes, the CRL number increases, and pruning works.
- **The JWT list:** its signature verifies, and a listed `jti` is rejected.
- **Fail closed:** no list, an expired list, a list with a bad signature, a list signed by another CA, and an older CRL number are all rejected.
- **End to end:** issue → verify (accepted) → revoke → refresh → verify (rejected), with the whole sequence visible in the trace.

## 8. Not in scope (v1)

- **Cascades** (revoke everything for an entry or device automatically): excluded by R2 (Q3).
- **Emergency CA rotation** (CA key compromise): not chosen. Recommended later as a written runbook, since it's the only way to invalidate *everything* at once.
- **A live per-request status service (OCSP):** R1 chose lists instead.

## 9. Open questions

1. **Q1: Timing.** Refresh interval **R** and list validity **V** (section 5).
2. **Q2: Reasons.** Is the reason list in section 3 right? Add or remove any?
3. **Q3: Cascades later?** Under R2, deleting an entry or revoking a device leaves already-issued identities valid until they expire, and the portal shows them (section 6). Do you want an optional "also revoke its active identities" checkbox in a later version?
4. **Q4: Button rename.** OK to rename the entry button from "Revoke" to "Delete entry", so "revoke" always means identity revocation?
