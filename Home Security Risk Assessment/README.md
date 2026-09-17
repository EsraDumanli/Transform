# Home Security Risk Assessment

A [Google ADK](https://google.github.io/adk-docs/) multi-agent tool that assesses the security posture of **your own device and home network** — read-only, defensive, and scoped to your private LAN only. It never guesses credentials, never touches anything outside your own subnet, and never modifies configuration.

Source lives in [`dumanli_security_posture/`](dumanli_security_posture/).

## What it does

Ask it for a full assessment and it will:

1. Inventory this device — OS patch level, installed packages, listening ports, firewall/FileVault/SIP state
2. Discover devices on the LAN and fingerprint the router (open ports, web admin banner)
3. Cross-reference discovered software/firmware versions against the public [NVD](https://nvd.nist.gov/) CVE database
4. Compute a single 0–100 **risk score** from everything gathered, with a transparent, inspectable formula (no black-box LLM guess)
5. Produce a prioritized patch plan (Critical → High → Medium → Low), with exact remediation commands

It can also just answer "what's my risk score?" (reusing findings already gathered in the conversation) or "show your topology" (it introspects its own agent graph and draws a live Mermaid diagram of itself).

## Architecture

One root agent (`dumanli_security_posture`) delegates to six sub-agents, each with its own narrow toolset:

| Agent | Tools | Job |
|---|---|---|
| `device_scanner_agent` | 7 | This Mac only: OS, packages, ports, security toggles |
| `network_recon_agent` | 5 | Private LAN + router only — never leaves the subnet |
| `vulnerability_analyst_agent` | 1 | Matches discovered software/firmware to public CVEs |
| `risk_score_agent` | 1 | Turns gathered findings into one 0–100 score |
| `patch_planner_agent` | 0 | Synthesis only — reasons over what it's handed |
| `topology_mapper_agent` | 1 | Explains this app's own architecture on request |

The default path runs the first five in sequence, each one handing more context to the next. Two shortcuts skip the pipeline: a risk-score-only question goes straight to `risk_score_agent` if findings already exist, and an architecture question goes straight to `topology_mapper_agent`.

## Setup

```bash
cd dumanli_security_posture
pip install -r requirements.txt
```

Copy the model/key template already in `.env` and fill in one of:

- `ANTHROPIC_API_KEY` — default model is `anthropic/claude-sonnet-5` via [LiteLLM](https://docs.litellm.ai/)
- `GOOGLE_API_KEY` — set `DUMANLI_MODEL=gemini-3.5-flash` (or another Gemini id) to call Gemini directly instead

**Note on cost:** running the agent (`adk run` / `adk web` / `adk eval`) makes real, billed model calls — it's not covered by a Claude.ai or Gemini subscription, since those don't grant API credits for third-party programs. The tools themselves (`tools/*.py`) are plain Python with no model dependency and can be called or tested for free — see Testing below.

## Running it

```bash
adk run dumanli_security_posture   # interactive CLI
adk web                            # web UI, from inside dumanli_security_posture/
```

## Testing

Two different things can be verified here, at two different costs:

**The scoring formula (free, no API key needed)** — plain pytest against `compute_risk_score()` directly:

```bash
pytest dumanli_security_posture/tests/test_risk_score.py -v
```

**The agent's tool-calling behavior (requires a configured model)** — ADK's own eval harness, checking whether the LLM calls the right tool with the right arguments from natural language:

```bash
adk eval dumanli_security_posture \
  dumanli_security_posture/risk_score_eval.evalset.json \
  --config_file_path dumanli_security_posture/risk_score_eval_config.json
```

## Scope & safety

Every tool call is read-only and refuses to act outside the user's own device or private subnet (enforced in code, not just prompted) — no login attempts, no credential guessing, no scanning of non-private address ranges.
