"""Search for job postings that match a candidate's resume, using Claude's
built-in web_search tool.

The web_search tool is executed server-side by the Anthropic API -- Claude
decides what to search for, the API runs the search and hands the results
back to Claude within the same request, and Claude keeps going until it's
ready to answer. So this module just needs to make one (possibly slow)
messages.create() call and parse a JSON block out of the final response.
"""
from __future__ import annotations

import json
import os
import re
from datetime import date, datetime
from typing import Iterable

import anthropic

DEFAULT_MODEL = os.environ.get("JOB_AGENT_MODEL", "claude-sonnet-5")
MAX_SEARCHES_PER_RUN = int(os.environ.get("JOB_AGENT_MAX_SEARCHES", "20"))

VALID_TIERS = {"strong", "good", "watch"}


class SearchError(RuntimeError):
    pass


def _client() -> anthropic.Anthropic:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise SearchError(
            "ANTHROPIC_API_KEY is not set. Copy .env.example to .env and add your key."
        )
    return anthropic.Anthropic(api_key=api_key)


def _build_prompt(resume_text: str, target_roles: str | None, companies: list[dict],
                   already_seen: list[dict]) -> str:
    company_lines = "\n".join(
        f"- {c['name']}" + (f" ({c['url']})" if c.get("url") else "")
        for c in companies
    ) or "(no specific companies listed -- search broadly based on the resume and target roles)"

    seen_lines = "\n".join(
        f"- {s['company']}: \"{s['role']}\"" + (f" (job_id={s['job_id']})" if s.get("job_id") else "")
        for s in already_seen
    ) or "(none yet -- this is the first run for this profile)"

    roles_line = target_roles.strip() if target_roles and target_roles.strip() else \
        "(not specified -- infer suitable target roles from the resume itself)"

    return f"""You are sourcing job postings for a candidate, based on their resume and a
list of target companies. Use the web_search tool to check each company's
careers page (and general job boards if a company has no clear careers page)
for open roles that plausibly fit this candidate. Do not fabricate postings --
only report roles you actually found via search, with a real link when the
search results give you one.

CANDIDATE RESUME:
---
{resume_text[:12000]}
---

TARGET ROLES / KEYWORDS (what kinds of roles to look for):
{roles_line}

COMPANIES TO CHECK:
{company_lines}

ALREADY FOUND ON A PREVIOUS RUN (do not report these again -- skip any posting
that matches one of these by company + job_id, or by company + a near-identical
title):
{seen_lines}

For each genuinely new posting you find, assess how well it fits the resume
above and bucket it into exactly one tier:
- "strong": seniority and subject matter both line up well with the resume
- "good": a solid match on seniority or subject matter, with some gap on the other
- "watch": worth knowing about but a real mismatch on seniority, subject matter,
  location, or similar -- still worth including, just flagged as a longer shot

When you are done searching, respond with ONLY a fenced json code block (no
other prose before or after it) containing a JSON array. Each element must
have exactly these fields:
  "company": string
  "role": string (exact job title)
  "location": string
  "posting_date": string (the date the listing states, or "not shown" if absent)
  "job_id": string (requisition/job ID if shown, else "")
  "link": string (direct URL to the posting, else "")
  "description": string (2-4 sentences: what the role actually involves, and a
     specific, concrete assessment of why it fits or doesn't fit this resume --
     seniority, subject matter, location, anything notable)
  "tier": one of "strong", "good", "watch"

If you find nothing new, respond with an empty JSON array: ```json
[]
```
"""


def _extract_json_array(text: str) -> list:
    match = re.search(r"```json\s*(.*?)\s*```", text, re.S)
    candidate = match.group(1) if match else text
    try:
        data = json.loads(candidate)
    except json.JSONDecodeError as e:
        raise SearchError(f"Couldn't parse Claude's response as JSON: {e}\n\nRaw text:\n{text[:2000]}")
    if not isinstance(data, list):
        raise SearchError(f"Expected a JSON array of postings, got: {type(data)}")
    return data


def _dedup_key(company: str, job_id: str, role: str) -> str:
    def norm(s: str) -> str:
        return re.sub(r"[^a-z0-9]+", "", (s or "").lower())

    company_n = norm(company)
    if job_id:
        return f"{company_n}:{norm(job_id)}"
    return f"{company_n}:{norm(role)}"


def search_jobs(
    *,
    resume_text: str,
    target_roles: str | None,
    companies: list[dict],
    already_seen: Iterable[dict],
    model: str = DEFAULT_MODEL,
) -> list[dict]:
    """Run one search pass and return a list of newly-found posting dicts,
    each ready to hand to db.insert_postings (already has a dedup_key).
    """
    client = _client()
    already_seen = list(already_seen)
    prompt = _build_prompt(resume_text, target_roles, companies, already_seen)

    response = client.messages.create(
        model=model,
        max_tokens=8000,
        system=(
            "You are a careful, factual job-search research assistant. You only "
            "report postings you actually found through search -- you never invent "
            "job titles, links, or companies. You follow the requested output "
            "format exactly."
        ),
        messages=[{"role": "user", "content": prompt}],
        tools=[
            {
                "type": "web_search_20250305",
                "name": "web_search",
                "max_uses": MAX_SEARCHES_PER_RUN,
            }
        ],
    )

    final_text = "".join(
        block.text for block in response.content if getattr(block, "type", None) == "text"
    )
    if not final_text.strip():
        raise SearchError("Claude's response had no text content to parse (possibly hit max_tokens).")

    raw_postings = _extract_json_array(final_text)

    seen_keys = {
        _dedup_key(s["company"], s.get("job_id", ""), s["role"]) for s in already_seen
    }

    results = []
    today = date.today().isoformat()
    for p in raw_postings:
        try:
            company = str(p["company"]).strip()
            role = str(p["role"]).strip()
        except (KeyError, TypeError):
            continue  # malformed entry, skip rather than fail the whole run
        job_id = str(p.get("job_id") or "").strip()
        key = _dedup_key(company, job_id, role)
        if key in seen_keys:
            continue
        seen_keys.add(key)  # guard against the model reporting the same posting twice

        tier = str(p.get("tier", "watch")).strip().lower()
        if tier not in VALID_TIERS:
            tier = "watch"

        results.append({
            "dedup_key": key,
            "company": company,
            "role": role,
            "location": str(p.get("location") or "").strip(),
            "posting_date": str(p.get("posting_date") or "").strip(),
            "job_id": job_id,
            "link": str(p.get("link") or "").strip(),
            "description": str(p.get("description") or "").strip(),
            "tier": tier,
            "found_date": today,
        })
    return results
