# macOS Secure Enclave Attestation for Laptops and MCP Clients: Design Draft (v0.1, for review)

**Goal:** before the SPIFFE server issues an identity (SVID) to an MCP client on your Mac, it must have evidence of **which Mac** is asking (device) and **which program** on it is asking (workload). That is what earns the dashboard's **High** confidence marker.

**Status:** design only, nothing built. Items marked **[OPEN]** need your decision ([section 10](#10-open-questions)). Items marked **[VERIFY]** are Apple-platform behaviours I'm not certain of. They must be confirmed on your Mac in Phase 0 before anything else is built. This cloud session runs on Linux and can't test any macOS-specific part.

## 1. Your constraints and what they mean

| Your answer | Consequence for the design |
|---|---|
| No MDM, and it stays that way | Apple's **Managed Device Attestation** (Apple-signed proof that a key lives in this Mac's Secure Enclave, plus device facts) is **not available**. |
| No Apple Developer Program membership | **App Attest** and Developer-ID signing/notarization of your own code aren't available. Your own binaries can only be **ad-hoc signed**. |
| Device + workload | Two separate proofs are needed: a Secure Enclave key for the device, and an OS-verified code signature for the workload. |
| Cover your own client **and** Claude Desktop / Cursor | Your own client can take part in the protocol (strong). Third-party apps can't be modified, so they can only be checked from outside (weaker). |

**The honest headline:** without MDM or Apple attestation, no outside party can prove that the device key is in the Secure Enclave. The design therefore uses **enrollment you approve**: the key is created in the Enclave on your Mac, and you approve its public key once in the portal. After that, the key can't be copied off the Mac, because the Enclave never releases it. But the "it's in the Enclave" fact rests on your enrollment approval, not on an Apple signature. Whether that counts as **High** is your call (**[OPEN Q1]**).

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

**Optional user presence** (**[OPEN Q3]**): the device key can require Touch ID for each use. That's stronger, but it prompts every time an SVID is issued or renewed.

## 5. Your own MCP client: target **High**

- Must be a **compiled, signed binary**, e.g. a small Swift CLI or app, or a compiled helper the client calls. A Python script is identified as "Python", so it can't be told apart from any other Python program (**[OPEN Q2]**).
- Signed **ad-hoc with Hardened Runtime**. Its **cdhash** is pinned in the registration entry.
- **Every rebuild changes the cdhash**, so a new build needs a re-approval. The portal shows "new build of `<name>` wants an identity; old cdhash → new cdhash" with Approve and Block (**[OPEN Q6]**).
- **Evidence:** enrolled Enclave device key, kernel audit token, OS-verified code signature, and nonce freshness. All are verified by the agent and server at issuance time.

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
| `macos-se-node+codesign-auditToken` (your own signed client through the agent) | **High** (subject to Q1) |
| `macos-codesign-parent` (Claude Desktop / Cursor seen from outside) | **Medium** |
| `macos-se-node` only (device proven, program unknown) | **Medium** |
| Existing methods (MCP config, A2A card, process name, IP:port) | **Low** |
| Docker image id, Kubernetes namespace/service account, process user + path | **Medium** |

## 8. Phases

| Phase | Where it can be done | What |
|---|---|---|
| **0. Spike** | **Your Mac**, local Claude Code session | Confirm every [VERIFY]: Enclave key from an ad-hoc-signed CLI; `LOCAL_PEERTOKEN` plus code signature lookup; reading Claude Desktop's and Cursor's Team IDs; Hardened Runtime with ad-hoc signing; running a launchd daemon as a dedicated user. Throwaway code; the output is a short findings note. |
| **1. Server side** | This cloud session | Enrollment, challenge and attested-issuance endpoints, new tools and selectors, portal Devices page and badges, trace events. Tested with a **software P-256 key standing in for the Enclave**, clearly marked as test-only. |
| **2. Node agent** | Your Mac | Swift `spiffe-node-agent`: Enclave key, Unix socket, audit-token and code-signature checks, signed requests, launchd installation script. |
| **3. Your own client** | Your Mac | A small signed client that gets an SVID from the agent and calls a demo MCP server over mTLS. |
| **4. Third-party mode** | Your Mac | Parent-process verification for your stdio MCP servers launched by Claude Desktop or Cursor. |
| **5. Hardening** | Both | Touch ID option (Q3), re-enrollment and rebuild flows, revocation, TTLs. |

Nothing is wired to real infrastructure until Phase 0's findings confirm the platform assumptions.

## 9. Not in scope (v1)

- Apple Managed Device Attestation and App Attest (excluded by your constraints).
- Windows or Linux laptops.
- Making Claude Desktop or Cursor present SVIDs themselves (not possible without the vendors' support).
- Proving device posture (SIP on, OS up to date). Without MDM, the agent can only **report** these facts; they're shown as "reported, not proven".

## 10. Open questions

1. **Q1: Does approved enrollment count as High?** The Enclave key can't leave the Mac, but no Apple signature proves it's in the Enclave; that rests on your approval. Options:
   - (a) High, if enrollment was approved and the workload signature is verified,
   - (b) Medium until an Apple-signed attestation is available (i.e. never, under your current constraints).
2. **Q2: Your own client's form.** It must be a compiled, signed binary for workload attestation to mean anything. Swift (native, easiest for the Apple security APIs), or another compiled language you prefer?
3. **Q3: Touch ID per use.** Require it for the device key (stronger, but it prompts on every issuance or renewal), only at enrollment, or not at all?
4. **Q4: SVID lifetime** for attested identities, e.g. 15 minutes with automatic renewal through the agent? Shorter limits damage from a compromise; longer reduces prompts and traffic.
5. **Q5: Installing the agent** as a launchd daemon under its own system user needs your admin password once. Acceptable?
6. **Q6: Rebuilds of your own client.** Every rebuild changes the cdhash. Re-approve each build in the portal, or pin something more stable (only possible with a Team ID, which needs a Developer membership)?
7. **Q7: Third-party apps to support first:** Claude Desktop, Cursor, or both? And which of your MCP servers would they launch?
