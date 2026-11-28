# macOS Secure Enclave Attestation for Laptops and MCP Clients: Design Draft (v0.2, for review)

**Goal:** before the SPIFFE server issues an identity (SVID) to an MCP client on your Mac, it must have evidence of **which Mac** is asking (device) and **which program** on it is asking (workload). Under your current constraints, the strongest result is **Medium** confidence (decision D1).

**Status:** design only, nothing built. Items marked **[OPEN]** need your decision ([section 10](#10-open-questions)).

## 0. Decisions made (v0.2)

| # | Question | Decision | What it means in the design |
|---|---|---|---|
| D1 | Q1: does approved enrollment count as High? | **No: Medium.** | Without an Apple-signed attestation (unavailable without MDM or a Developer membership), no method reaches **High**. Your own attested client is **Medium**. **High** stays reserved in the rubric with nothing mapped to it, for a future vendor-attested method. |
| D2 | Q2: what language for your own client and the node agent? | **Swift** (you asked for the best option; this is my recommendation, with reasons in section 5). | The node agent and your own MCP client (or its signed helper) are written in Swift. The SPIFFE server and portal stay in Python. |
| D3 | Q3: when is Touch ID required? | **At enrollment only.** | Enrolling the Mac requires your fingerprint on the Mac itself, so malware can't silently enroll a device. Day-to-day identity issuance doesn't prompt (section 4.1). |
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

4. **Q4: SVID lifetime** for attested identities, e.g. 15 minutes with automatic renewal through the agent? Shorter limits damage from a compromise; longer reduces traffic.
5. **Q5: Installing the agent** as a launchd daemon under its own system user needs your admin password once (and Touch ID at enrollment, per D3). Acceptable?
7. **Q7: Third-party apps to support first:** Claude Desktop, Cursor, or both? And which of your MCP servers would they launch?

**New, from your decisions:**

8. **Q8: Keeping the badges meaningful.** With D1, your fully attested client is **Medium**, the same as Claude Desktop seen from outside, and the same as a Docker image ID. Options:
   - (a) keep these at **Medium** and rely on the badge's hover text (method and reason) to tell them apart,
   - (b) lower the weaker ones (third-party seen from outside, device-only) to **Low**, so **Medium** means "device and program both verified".

   I lean towards (b), because a badge people trust at a glance should mean one thing.
