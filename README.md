# Transform

A personal lab for experimenting with agentic AI — across personal projects and things closer to my day job in enterprise security and networking.

I'm still very much learning this space. Every project in here started as "can an agent actually do this?" and turned into hours of being genuinely awed by what these tools can build when you give them a clear problem and get out of the way. None of this is production-hardened, and I'm sure some of it is over-engineered in places and under-engineered in others, in ways I can't fully see yet. If you spot something, or know a better way to do it, I'd genuinely like to hear it.

## What's here

- **[Home Security Risk Assessment](Transform/Home%20Security%20Risk%20Assessment)** — A multi-agent home network and device security scanner built on Google's ADK. Six sub-agents each own a narrow slice (device posture, LAN discovery, CVE cross-referencing against the NVD, ...) and roll up into one inspectable 0–100 risk score with a prioritized patch plan. Read-only and scoped to my own LAN by design — it never guesses credentials or touches anything outside my own subnet.
- **[Job Search Agent](Transform-addition/job-search-agent)** — A self-hosted tool that reads a resume, checks target companies' career pages using Claude's web search, and scores matches on a dashboard. Runs on demand or on a schedule; every clone starts completely empty, and nothing is shared between instances.
- **[SASE Agentic AIOps](Transform/sase_agentic_aiops)** — A small pipeline pairing real ML anomaly detectors (Isolation Forest, a time-series baseline, DBSCAN peer clustering) with an agent that correlates their output into incidents, triages severity, and proposes an action — gated behind human approval before anything mutates a real system. Closest to what I think about all day at work.

More will land here as I keep poking at this. Expect it to stay a little messy and a lot experimental — this is a workbench, not a portfolio.

## Why this exists

A few honest reasons:

1. I want to get hands-on with agentic systems, not just read about them — the fastest way I know to actually understand a technology is to build something real with it and watch where it breaks.
2. I keep being surprised by how far you can get with a clear problem statement, a tight feedback loop, and a willingness to throw away the first attempt. That seemed worth documenting as I go.
3. I'd rather learn in public and get corrected than learn alone and stay wrong. If something here reflects a bad pattern or a naive assumption, please tell me — that's genuinely the point of putting it up.

## How these get built

Every project here was built working alongside Claude — I bring the problem, the domain judgment, and (mostly) the taste; the agent does a lot of the typing and a fair amount of the architecture thinking, with me reviewing and steering throughout. That collaboration is part of what I find worth sharing here, not just the code it produces.

## Feedback welcome

Questions, "have you tried...", "this is a bad idea because...", or just "here's how I'd have done it" — all genuinely welcome. Open an issue, leave a comment on a file, or reach out directly.
