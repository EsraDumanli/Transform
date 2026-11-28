# macOS Secure Enclave Attestation for Laptops and MCP Clients: Design (v0.3; Phase 1 implemented)

**Goal:** before the SPIFFE server issues an identity (SVID) to an MCP client on your Mac, it must have evidence of **which Mac** is asking (device) and **which program** on it is asking (workload). Under your current constraints, the strongest result is **Medium** confidence (decision D1).

**Status:** Phase 1 (the server side) is **implemented** on the `SPIFFE-Changes` branch: enrollment, approval, challenges, attested issuance, build approvals, badges, policy tools, trace. It's tested with a software key standing in for the Enclave (`scripts/dev_fake_node_agent.py`, test only). Phases 0 (remaining checks), 2, 3 and 4 need your Mac. Items marked **[OPEN]** need your decision ([section 10](#10-open-questions)).

## 0. Decisions made (v0.2)

| # | Question | Decision | What it means in the design |
|---|---|---|---|
| D1 | Q1: does approved enrollment count as High? | **No: Medium.** | Without an Apple-signed attestation (unavailable without MDM or a Developer membership), no method reaches **High**. Your own attested client is **Medium**. **High** stays reserved in the rubric with nothing mapped to it, for a future vendor-attested method. |
| D2 | Q2: what language for your own client and the node agent? | **Swift** (you asked for the best option; this is my recommendation, with reasons in section 5). | The node agent and your own MCP client (or its signed helper) are written in Swift. The SPIFFE server and portal stay in Python. |
| D3 | Q3: when is Touch ID required? | **At enrollment only.** | Enrolling the Mac requires your fingerprint on the Mac itself, so malware can't silently enroll a device. Day-to-day identity issuance doesn't prompt (section 4.1). |
| D5 | Q8: what do the badges mean? | **Weaker methods are Low.** | Claude Desktop seen from outside, and device-only, are **Low**. **Medium** means the device and the program were both verified, or a trusted platform observation (Docker image hash, Kubernetes service account, process path). |
| D6 | Q4: identity lifetime | **30 minutes.** | `attested_svid_ttl_minutes: 30` in the server config, capped by `max_ttl_minutes: 30` in the tool policy. |
| D7 | Q5: install the agent as a background service | **OK.** | A launchd daemon under its own system user, installed with your admin password once. |
| D8 | Q7: third-party apps | **Claude Desktop only.** | Phase 4 targets Claude Desktop launching your stdio MCP servers. Cursor is out of scope. |
| D4 | Q6: re-approve every rebuild of your client? | **Yes.** | Each new build's code fingerprint (cdhash) must be approved in the portal before it can get an identity. The old build's entry stays until you revoke it (section 5). |
 Items marked **[VERIFY]** are Apple-platform behaviours I'm not certain of. They must be confirmed on your Mac in Phase 0 before anything else is built. This cloud session runs on Linux and can't test any macOS-specific part.

## 1. Your constraints and what they mean

| Your answer | Consequence for the design |
|---|---|
| No MDM, and it stays that way | Apple's **Managed Device Attestation** (Apple-signed proof that a key lives in this Mac's Secure Enclave, plus device facts) is **not available**. |
| No Apple Developer Program membership | **App Attest** and Developer-ID signing/notarization of your own code aren't available. Your own binaries can only be **ad-hoc signed**. |
| Device + workload | Two separate proofs are needed: a Secure Enclave key for the device, and an OS-verified code signature for the workload. |
| Cover your own client **and** Claude Desktop / Cursor | Your own client can take part in the protocol (strong). Third-party apps can't be modified, so they can only be checked from outside (weaker). |

**The honest headline:** without MDM or Apple attestation, no outside party can prove that the device key is in the Secure Enclave. The design therefore uses **enrollment you approve**: the key is created in the Enclave on your Mac, and you approve its public key once in the portal. After that, the key can't be copied off the Mac, because the Enclave never releases it. But the "it's in the Enclave" fact rests on your enrollment approval, not on an Apple signature, so it's rated **Medium** (D1).

## 2. Building blocks

| Block | What it gives | Limits |
|---|---|---|
| **Secure Enclave P-256 key** (CryptoKit `SecureEnclave.P256.Signing`) | Private key generated and kept inside the Enclave; it can sign but can't be exported. A stolen key blob is useless on another Mac. | Any process that can load the blob **on the same Mac** and is allowed to use it can sign, so on-device access control matters (section 4). **[VERIFY]** that an ad-hoc-signed command-line tool can create and use Enclave keys without extra entitlements. |
| **Audit token of the caller** (`getsockopt(LOCAL_PEERTOKEN)` on a Unix socket) | Kernel-provided identity of the process on the other end of the socket. Unlike a PID, it can't be confused with a reused process ID. | Only for processes that connect to our socket. **[VERIFY]** availability and behaviour on your macOS version. |
| **Code signature check** (`SecCodeCopyGuestWithAttributes` with the audit token, then `SecCodeCheckValidity` against a requirement) | The OS verifies what signed the running program: the vendor's **Team ID** for notarized apps (Claude Desktop, Cursor), or the **cdhash** (exact build fingerprint) for ad-hoc-signed code. | Our own ad-hoc code has no Team ID, so it's pinned by cdhash, which changes on every rebuild. **Scripts can't be identified this way**: a Python client shows up as the Python interpreter, not your script. |
| **Hardened Runtime** (`codesign -o runtime`) | Blocks code injection and debugger attachment into the signed process, so a verified signature means the code running is the code that was signed. | **[VERIFY]** that it can be applied to ad-hoc-signed binaries and is enforced. |

## 3. Architecture

```
 Your Mac                                                     SPIFFE server
 ┌────────────────────────────────────────────────────┐      ┌───────────────────────────┐
 │  MCP client (your own, signed binary)              │      │                           │
 │     │ 1. "give me my SVID"  (Unix socket)          │      │  node registry            │
 │     ▼                                              │      │  (enrolled device keys)   │
 │  spiffe-node-agent  (runs as its own system user)  │ 3.   │                           │
 │   • reads caller's audit token                     │─────►│  verifies:                │
 │   • 2. checks caller's code signature (OS)         │ TLS  │   • node signature over   │
 │   • holds the Secure Enclave device key            │      │     the server's nonce    │
 │   • signs {nonce, workload evidence} with it       │◄─────│   • registration entry    │
 │     │ 4. SVID back to the client                   │ 4.   │     matches the evidence  │
 │     ▼                                              │      │   • tool policy allows it │
 │  MCP client uses the SVID (mTLS / JWT) ──────────► MCP server (verifies the SVID)     │
 └────────────────────────────────────────────────────┘      └───────────────────────────┘
```

1. The **MCP client** connects to the node agent's local socket and asks for its identity.
2. The **node agent** reads the client's audit token from the kernel and asks macOS to verify the client's code signature. It collects workload evidence: Team ID, signing identifier, cdhash, whether Hardened Runtime is on, and the executable path.
3. The agent asks the server for a **fresh nonce**, then signs `{nonce, node id, workload evidence}` with the **Secure Enclave key**. The server checks:
   - the signature against the **enrolled** device key,
   - that the nonce is fresh and single-use, so a request can't be replayed,
   - that a **registration entry** matches the evidence (e.g. `macos:team_id:XXXXXXXXXX` + `macos:signing_id:com.example.mcp-client` + `node:id:<enrolled node>`),
   - that the tool policy allows attested issuance.
4. The server returns a short-lived **SVID**. The client uses it to authenticate to MCP servers.

**Why a separate node agent (the SPIRE pattern)?** The device key must not be usable by every program on the Mac. Only the agent, running as a dedicated system user, can read the key blob. Programs can't use the key directly; they can only ask the agent, and the agent only answers programs whose code signature matches a registration entry.

## 4. On-device protection

| Threat | Mitigation | Residual risk |
|---|---|---|
| Malware running as you copies the key blob | Blob stored in a directory owned by the agent's dedicated user with mode `0700`, so your user account can't read it. Even if it's stolen, it's useless off this Mac. | Malware running as **root** can use the agent's key. No software design defends against root on the same machine. |
| Malware pretends to be your MCP client | The agent verifies the caller's code signature through its audit token. Malware has a different cdhash or Team ID. | If malware can modify and re-sign your ad-hoc binary, its cdhash changes, so it won't match the pinned entry. |
| Code injected into a legitimate client | Hardened Runtime on the clients you build; notarized third-party apps already use it. | **[VERIFY]** for ad-hoc signing. |
| Replay of a captured request | Server nonce, single use, short expiry. | — |
| Rogue device enrolls | Enrollment needs your approval in the portal, showing the key fingerprint, which you compare with what the agent prints on the Mac. | Approving the wrong fingerprint. The UI shows a short code to compare. |
| Requests for identities outside the plan | Tool policy prefixes and registration entries, as today. Attested issuance is a new tool with its own limits (section 7). | — |

### 4.1 Touch ID at enrollment (D3)

- **Who enrolls:** enrollment is a separate command you run in your own logged-in session, e.g. `spiffe-node-agent enroll`. A background daemon generally can't show a Touch ID prompt (**[VERIFY]**), so the agent can't enroll itself.
- **The command:**
  1. asks for **Touch ID** (LocalAuthentication); no fingerprint means no enrollment,
  2. creates the Secure Enclave device key,
  3. hands the key to the agent's protected directory (this needs your admin password once),
  4. sends the enrollment request,
  5. prints the key fingerprint and short code for you to compare in the portal.
- **What Touch ID proves, and what it doesn't:** it proves a person with your fingerprint was at the Mac when it enrolled, which stops silent enrollment by malware. It does **not** give the server cryptographic proof that Touch ID happened (again, no Apple attestation). The server's trust still comes from your portal approval. Both steps are required.
- **Day to day:** the key itself isn't Touch ID-protected, so issuing and renewing SVIDs never prompts.
- **[VERIFY]:** that a Secure Enclave key created by your user's enrollment command can then be used by the agent running as its own system user. If not, enrollment has to run under the agent's user, with a different way of showing the Touch ID prompt.

## 5. Your own MCP client: target **Medium** (the strongest available, D1)

- Must be a **compiled, signed binary**. A Python script is identified as "Python", so it can't be told apart from any other Python program.
- **Language: Swift (D2).** Why Swift over the alternatives:
  - **Native access:** the Secure Enclave (CryptoKit), Touch ID (LocalAuthentication) and code-signature checks (Security framework) are Apple APIs with first-class Swift interfaces. Go, Rust or Python would need extra bridging layers to reach them, which means more code and more places for mistakes.
  - **Builds without a paid account:** the Swift compiler and `codesign` come with the free Xcode Command Line Tools.
  - **Ad-hoc signing works:** no Developer membership is needed for that.
  - **One language for both:** the node agent and your client.
- **Rebuilds (D4):** every build gets a new cdhash. The build script prints it, and the portal shows the pending approval.
- Signed **ad-hoc with Hardened Runtime**. Its **cdhash** is pinned in the registration entry.
- **Every rebuild changes the cdhash, and each new build must be approved (D4):**
  - the portal shows "new build of `<name>` wants an identity; old cdhash → new cdhash" with Approve and Block,
  - until approved, the new build gets no identity,
  - the old build's entry stays valid until you revoke it, so you can roll back.
- **Evidence:** enrolled Enclave device key, kernel audit token, OS-verified code signature, and nonce freshness. All are verified by the agent and server at issuance time. Rated **Medium** (D1): the strongest result available without Apple attestation.

## 6. Claude Desktop and Cursor (third party): honest target **Medium**

These apps don't know about our agent, so they can't ask for an SVID themselves. What we *can* do:

- **Verify the app's installation:** check the signature of `/Applications/Claude.app` or `Cursor.app` against its vendor's Team ID (from its notarized signature), using `SecStaticCode`. That proves the installed app is genuine.
- **Verify who launched our MCP server:** when Claude Desktop starts one of *your* stdio MCP servers, that server (our signed code) asks the agent to identify its **parent process** and verify the parent's code signature.
- **Why that's weaker:**
  - the parent is found by PID, which can be reused (**[VERIFY]** whether an audit token for the parent is available without special privileges),
  - the app never proves anything itself; we only observe it,
  - the identity issued goes to **your MCP server process**, labelled as launched by a verified Claude Desktop, not to Claude Desktop itself.
- **Dashboard marker:** `macos-codesign-parent`, **Medium**, with the reason "vendor-signed app verified from outside; app doesn't take part in attestation".

## 7. Server, policy, portal and trace changes

- **New endpoints:**
  - `POST /v1/node/enroll`: the agent submits its device public key and the device facts it can observe. The node starts as **pending**.
  - `POST /v1/node/challenge`: issues a nonce.
  - `POST /v1/node/svid`: attested issuance, authenticated by the Enclave signature instead of the admin token.
- **New tools in the locked tool policy** (same rules as today, every limit required):
  - `server.node.enroll`: limits `max_pending`, plus which device facts are required.
  - `server.svid.attested`: limits `spiffe_id_prefixes`, `allowed_team_ids`, `require_hardened_runtime`, `max_ttl_minutes`.
- **New selector types:** `node:id:<fingerprint>`, `macos:team_id:<id>`, `macos:signing_id:<id>`, `macos:cdhash:<hash>`, `macos:hardened_runtime:true`, `macos:parent_team_id:<id>`.
- **Portal:**
  - a **Devices** list with pending enrollment (fingerprint and short code) and Approve, Block and Revoke buttons,
  - new-build approvals (Q6),
  - the confidence **badge** on every workload and identity (H green, M amber, L grey), with the method and reason.
- **Trace:** enrollment, challenge, attested issuance, and every failed check (wrong signature, unknown node, signature mismatch, replayed nonce) become trace events with the node id and workload signing id, never key material.
- **Confidence rubric** in the locked policy file. Methods not listed fall back to **Low**:

| Method | Proposed confidence |
|---|---|
| *(reserved, nothing mapped yet)* vendor-attested device + workload | **High** |
| `macos-se-node+codesign-auditToken` (your own signed client through the agent) | **Medium** (D1) |
| `macos-codesign-parent` (Claude Desktop / Cursor seen from outside) | **Medium** or **Low** (**[OPEN Q8]**) |
| `macos-se-node` only (device proven, program unknown) | **Medium** or **Low** (**[OPEN Q8]**) |
| Existing methods (MCP config, A2A card, process name, IP:port) | **Low** |
| Docker image id, Kubernetes namespace/service account, process user + path | **Medium** |

## 8. Phases

| Phase | Where it can be done | What |
|---|---|---|
| **0. Spike** | **Your Mac**, local Claude Code session | Confirm every [VERIFY]: Touch ID prompt from a user-session command; Enclave key usable by the agent's separate user; Enclave key from an ad-hoc-signed CLI; `LOCAL_PEERTOKEN` plus code signature lookup; reading Claude Desktop's and Cursor's Team IDs; Hardened Runtime with ad-hoc signing; running a launchd daemon as a dedicated user. Throwaway code; the output is a short findings note. |
| **1. Server side** | This cloud session | Enrollment, challenge and attested-issuance endpoints, new tools and selectors, portal Devices page and badges, trace events. Tested with a **software P-256 key standing in for the Enclave**, clearly marked as test-only. |
| **2. Node agent** | Your Mac | Swift `spiffe-node-agent`: Enclave key, Unix socket, audit-token and code-signature checks, signed requests, launchd installation script. |
| **3. Your own client** | Your Mac | A small signed client that gets an SVID from the agent and calls a demo MCP server over mTLS. |
| **4. Third-party mode** | Your Mac | Parent-process verification for your stdio MCP servers launched by Claude Desktop or Cursor. |
| **5. Hardening** | Both | Re-enrollment and rebuild flows, revocation, TTLs. |

Nothing is wired to real infrastructure until Phase 0's findings confirm the platform assumptions.

## 9. Not in scope (v1)

- Apple Managed Device Attestation and App Attest (excluded by your constraints).
- Windows or Linux laptops.
- Making Claude Desktop or Cursor present SVIDs themselves (not possible without the vendors' support).
- Proving device posture (SIP on, OS up to date). Without MDM, the agent can only **report** these facts; they're shown as "reported, not proven".

## 10. Open questions

**Answered:** Q1 (D1), Q2 (D2), Q3 (D3), Q6 (D4).

**Still open:**

All questions so far are answered (D1–D8). **Phase 0 status:** Touch ID from the enrollment command is **confirmed** on your Mac. The other [VERIFY] items are still to check before Phase 2.

**Answered (kept for reference):**

8. **Q8: Keeping the badges meaningful** (→ D5). With D1, your fully attested client is **Medium**, the same as Claude Desktop seen from outside, and the same as a Docker image ID. Options:
   - (a) keep these at **Medium** and rely on the badge's hover text (method and reason) to tell them apart,
   - (b) lower the weaker ones (third-party seen from outside, device-only) to **Low**, so **Medium** means "device and program both verified".

   I lean towards (b), because a badge people trust at a glance should mean one thing.

## 11. Wire protocol (implemented in Phase 1, for the Swift agent to follow)

All requests are HTTPS to the SPIFFE server, verified against its `bundle.pem`. JSON bodies.

**Enroll**, from the user-session enrollment command. It's authenticated with the **admin token**, and the result is still only *pending*:
```
POST /v1/nodes/enroll           Authorization: Bearer <admin token>
{"public_key": "<PEM SubjectPublicKeyInfo, EC P-256>",
 "facts": {"hostname": "...", "model": "...", "macos_version": "...", "touch_id_confirmed": true}}
→ 201 {"id": "<sha256 of the DER public key, hex>", "short_code": "ABCD-1234", "status": "pending", ...}
```
- **Facts** are reported, not proven. Allowed keys: `hostname`, `model`, `macos_version`, `touch_id_confirmed`, `software_key_test_only`. Anything else is rejected.
- **Approval:** a person approves in the portal after comparing `short_code` with what the command printed.

**Challenge.** No admin token is needed; the node must be **approved**:
```
POST /v1/node/challenge   {"node_id": "<id>"}
→ 200 {"nonce": "<random>", "expires_at": <unix seconds>}     (single use, 60 s, bound to this node)
```

**Attested SVID.** No admin token; the request is signed with the **device key**:
```
POST /v1/node/svid
{"request": {"node_id": "<id>", "nonce": "<from challenge>", "spiffe_id": "spiffe://<td>/mac/...",
             "csr": "<PEM CSR for the workload's own key>",
             "workload": {"signing_id": "com.example.mcp-client", "team_id": null | "ABCDE12345",
                          "cdhash": "<40 lowercase hex>", "hardened_runtime": true,
                          "path": "/absolute/path/to/binary",
                          "parent": null | {"signing_id": "...", "team_id": "...", "cdhash": "..."}}},
 "signature": "<base64 DER ECDSA-SHA256 over canonical_json(request)>"}
→ 200 {"svid": "<PEM>", "bundle": "<PEM>", "ttl_minutes": 30,
       "attestation": {"method": "macos-se-node+codesign", "confidence": "medium"}}
→ 403 {"error": "...new build...", "build_id": "..."}   when only the cdhash differs from an approved entry (D4)
```
- **`canonical_json`:** keys sorted, no whitespace (`","` and `":"` separators), UTF-8, non-ASCII not escaped. Both sides must produce identical bytes. The Python reference is `spiffe_identity/nodes.py: canonical_json`.
- **Server checks, in order:**
  1. the node is approved,
  2. the signature verifies against the enrolled key,
  3. the nonce is valid, unused and belongs to this node,
  4. the evidence is valid (unknown fields rejected),
  5. a registration entry for that SPIFFE ID contains `node:id:<this node>`, and **all** its selectors appear in the selectors the server derives from the evidence,
  6. the tool policy allows `server.svid.attested`: prefix, TTL, Hardened Runtime.
- **Trace:** every failure is a `DENY` event with the reason, never key material.

**Selectors derived from evidence** (by the server, never sent by the caller): `node:id:`, `macos:signing_id:`, `macos:cdhash:`, `macos:hardened_runtime:true|false`, `macos:team_id:` (if present), and `macos:parent_signing_id:`, `macos:parent_team_id:`, `macos:parent_cdhash:` (if a parent was given).
