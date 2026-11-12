// Agent Identity Portal front end.
// Every value from the scan or the server is inserted with textContent, never
// innerHTML: agent cards, labels and command lines are untrusted input.
"use strict";

const TOKEN = document.querySelector('meta[name="portal-token"]').content;
const $ = (id) => document.getElementById(id);
let state = null;
const open = new Set(); // proposal ids whose detail row is expanded

function el(tag, opts = {}, ...children) {
  const n = document.createElement(tag);
  if (opts.cls) n.className = opts.cls;
  if (opts.text !== undefined) n.textContent = opts.text;
  if (opts.title) n.title = opts.title;
  for (const c of children) if (c) n.append(c);
  return n;
}

function banner(msg, kind = "error") {
  const b = $("banner");
  if (!msg) { b.hidden = true; return; }
  b.hidden = false;
  b.className = `banner ${kind}`;
  b.textContent = msg;
}

async function api(path, body) {
  const opts = body === undefined
    ? { method: "GET" }
    : { method: "POST", headers: { "Content-Type": "application/json", "X-Portal-Token": TOKEN }, body: JSON.stringify(body) };
  const res = await fetch(path, opts);
  let data = null;
  try { data = await res.json(); } catch { /* non-JSON error */ }
  if (!res.ok) throw new Error((data && data.error) || `HTTP ${res.status}`);
  return data;
}

// ---- status -------------------------------------------------------------------

const sameSelectors = (a, b) => a.length === b.length && [...a].sort().every((v, i) => v === [...b].sort()[i]);

function statusOf(p) {
  if (!p.spiffe_id) return { key: "unassigned", label: "Unassigned", reason: (p.problems || []).join("; ") || "no identity proposed" };
  if (!state.entries) return { key: "unknown", label: "Unknown", reason: "SPIFFE server unreachable" };
  const entry = state.entries.find((e) => e.spiffe_id === p.spiffe_id && sameSelectors(e.selectors, p.workload.selectors));
  if (entry) return { key: "registered", label: "Registered", entry };
  const other = state.entries.some((e) => e.spiffe_id === p.spiffe_id);
  return { key: "pending", label: "Awaiting approval", reason: other ? "this ID is already registered to different selectors" : "" };
}

// ---- rendering ----------------------------------------------------------------

function render() {
  $("td").textContent = state.trust_domain;
  $("approver").textContent = state.approver;
  const scan = state.scan;
  $("scanned").textContent = scan ? `Last scan ${new Date(scan.scanned_at).toLocaleString()}` : "No scan yet";

  if (state.scan_error) banner(`Saved scan could not be loaded: ${state.scan_error}`);
  else if (state.entries_error) banner(`Could not reach the SPIFFE server, so registration status is unknown: ${state.entries_error}`);
  else banner(null);

  const proposals = scan ? scan.proposals : [];
  const statuses = new Map(proposals.map((p) => [p.id, statusOf(p)]));
  const count = (k) => [...statuses.values()].filter((s) => s.key === k).length;
  $("c-total").textContent = scan ? proposals.length : "–";
  $("c-registered").textContent = state.entries ? state.entries.length : "–";
  $("c-pending").textContent = scan ? count("pending") : "–";
  $("c-unassigned").textContent = scan ? count("unassigned") : "–";

  renderSources(scan);
  renderKindFilter(proposals);
  renderWorkloads(proposals, statuses);
  renderEntries(proposals);
}

function renderSources(scan) {
  const box = $("sources");
  box.replaceChildren();
  const notes = $("notes");
  notes.replaceChildren();
  if (!scan) {
    box.append(el("p", { cls: "empty", text: "No scan yet. Click “Scan now” to run the discovery sources in your config." }));
    return;
  }
  for (const s of scan.sources) {
    const card = el("div", { cls: `src${s.error ? " err" : ""}` },
      el("div", { cls: "name", text: s.source }),
      el("div", { cls: "meta", text: s.error ? `Failed: ${s.error}` : `${s.workload_count} workload(s)` }));
    if (s.warnings && s.warnings.length) {
      const d = el("details", {}, el("summary", { text: `${s.warnings.length} warning(s)` }));
      const ul = el("ul");
      s.warnings.forEach((w) => ul.append(el("li", { text: w })));
      d.append(ul);
      card.append(d);
    }
    box.append(card);
  }
  (scan.notes || []).forEach((n) => notes.append(el("li", { text: n })));
}

function renderKindFilter(proposals) {
  const sel = $("f-kind");
  const current = sel.value;
  const kinds = [...new Set(proposals.map((p) => p.workload.kind))].sort();
  sel.replaceChildren(el("option", { text: "All kinds" }));
  sel.firstChild.value = "";
  kinds.forEach((k) => { const o = el("option", { text: k }); o.value = k; sel.append(o); });
  sel.value = kinds.includes(current) ? current : "";
}

function matchesFilters(p, st) {
  const kind = $("f-kind").value, status = $("f-status").value, q = $("f-text").value.trim().toLowerCase();
  if (kind && p.workload.kind !== kind) return false;
  if (status && st.key !== status) return false;
  if (!q) return true;
  const hay = [p.workload.name, p.workload.kind, p.workload.source, p.spiffe_id || "",
    ...p.workload.selectors, ...Object.entries(p.workload.attributes).flat()].join("\n").toLowerCase();
  return hay.includes(q);
}

function renderWorkloads(proposals, statuses) {
  const body = $("wl-body");
  body.replaceChildren();
  const visible = proposals.filter((p) => matchesFilters(p, statuses.get(p.id)));
  const empty = $("wl-empty");
  empty.hidden = visible.length > 0;
  empty.textContent = proposals.length ? "No workloads match these filters." : "Nothing discovered yet.";

  for (const p of visible) {
    const st = statuses.get(p.id);
    const tr = el("tr", { cls: `row${open.has(p.id) ? " open" : ""}` });
    tr.tabIndex = 0;
    tr.setAttribute("aria-expanded", open.has(p.id));

    const name = el("td", {}, el("span", { cls: "chev", text: "▸" }), el("span", { cls: "wname", text: ` ${p.workload.name}` }));
    const idCell = el("td", { cls: "id mono" });
    if (p.spiffe_id) {
      idCell.append(document.createTextNode(p.spiffe_id));
      if ((p.assigned_by || "").startsWith("llm:")) {
        idCell.append(" ", el("span", { cls: "pill llm", text: "LLM proposal", title: `${p.assigned_by} · confidence ${p.confidence || "n/a"}` }));
      }
    } else {
      idCell.append(el("span", { cls: "muted", text: "—" }));
    }
    const statusCell = el("td", {}, el("span", { cls: `pill ${st.key}`, text: st.label }));
    if (st.reason) statusCell.append(el("span", { cls: "reason", text: st.reason }));

    const act = el("td", { cls: "act" });
    if (st.key === "pending") {
      const b = el("button", { cls: "btn small primary", text: "Approve" });
      b.type = "button";
      b.addEventListener("click", (ev) => { ev.stopPropagation(); approve(p, b); });
      act.append(b);
    } else if (st.key === "registered") {
      const b = el("button", { cls: "btn small danger", text: "Revoke" });
      b.type = "button";
      b.addEventListener("click", (ev) => { ev.stopPropagation(); revoke(st.entry, b); });
      act.append(b);
    }

    tr.append(name, el("td", { cls: "hide-sm" }, el("span", { cls: "tag", text: p.workload.kind })), el("td", { cls: "hide-sm", text: p.workload.source }), idCell, statusCell, act);
    const toggle = () => { open.has(p.id) ? open.delete(p.id) : open.add(p.id); render(); };
    tr.addEventListener("click", toggle);
    tr.addEventListener("keydown", (ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); toggle(); } });
    body.append(tr);
    if (open.has(p.id)) body.append(detailRow(p, st));
  }
}

function detailRow(p, st) {
  const row = $("detail-tpl").content.firstElementChild.cloneNode(true);
  const kv = row.querySelector(".kv");
  const attrs = Object.entries(p.workload.attributes).sort(([a], [b]) => a.localeCompare(b));
  if (!attrs.length) kv.append(el("tr", {}, el("td", { text: "(none observed)" })));
  for (const [k, v] of attrs) kv.append(el("tr", {}, el("td", { cls: "mono", text: k }), el("td", { cls: "mono", text: v })));

  const sel = row.querySelector(".sel");
  p.workload.selectors.forEach((s) => sel.append(el("li", { cls: "mono", text: s })));

  const dl = row.querySelector(".assign");
  const add = (k, v, cls) => { dl.append(el("dt", { text: k }), el("dd", { cls, text: v })); };
  add("Identity", p.spiffe_id || "none", "mono");
  if (p.assigned_by) add("Chosen by", p.assigned_by);
  if (p.confidence) add("Confidence", p.confidence);
  if (p.rationale) add("Why", p.rationale);
  (p.problems || []).forEach((x) => add("Problem", x, "warnline"));
  if (st.entry) {
    add("Approved by", st.entry.approved_by);
    add("Registered", new Date(st.entry.created_at).toLocaleString());
    add("Entry id", st.entry.id, "mono");
  }
  if (p.workload.kind === "network-service") add("Note", "IP:port selectors are weak: anything that takes over this address inherits the identity.", "warnline");
  return row;
}

function renderEntries(proposals) {
  const body = $("en-body");
  body.replaceChildren();
  const empty = $("en-empty");
  if (!state.entries) {
    empty.hidden = false;
    empty.textContent = "SPIFFE server unreachable: registered identities can't be listed.";
    return;
  }
  empty.hidden = state.entries.length > 0;
  empty.textContent = "No identities registered yet. Approve a workload above to register one.";
  for (const e of state.entries) {
    const inScan = proposals.some((p) => p.spiffe_id === e.spiffe_id && sameSelectors(e.selectors, p.workload.selectors));
    const idCell = el("td", { cls: "id mono", text: e.spiffe_id });
    if (!inScan) idCell.append(el("span", { cls: "reason", text: "not seen in the last scan" }));
    const b = el("button", { cls: "btn small danger", text: "Revoke" });
    b.type = "button";
    b.addEventListener("click", () => revoke(e, b));
    body.append(el("tr", {}, idCell, el("td", { cls: "hide-sm", text: e.source || "—" }), el("td", { cls: "hide-sm", text: e.assigned_by || "—" }),
      el("td", { text: e.approved_by }), el("td", { text: new Date(e.created_at).toLocaleString() }), el("td", { cls: "act" }, b)));
  }
}

// ---- actions ------------------------------------------------------------------

async function run(btn, label, fn) {
  const old = btn.textContent;
  btn.disabled = true;
  btn.textContent = label;
  try {
    state = await fn();
    render();
    return true;
  } catch (err) {
    banner(err.message);
    btn.disabled = false;
    btn.textContent = old;
    return false;
  }
}

async function approve(p, btn) {
  const lines = [
    `Approve this identity?\n\n${p.spiffe_id}\n\nfor ${p.workload.name} (${p.workload.kind})`,
    `Selectors: ${p.workload.selectors.join(", ")}`,
    `Chosen by: ${p.assigned_by}`,
  ];
  if ((p.assigned_by || "").startsWith("llm:")) lines.push("This was proposed by an LLM. Check it against what you know about this workload.");
  if (p.workload.kind === "network-service") lines.push("Warning: IP:port selectors are weak.");
  lines.push(`It will be recorded as approved by ${state.approver}.`);
  if (!confirm(lines.join("\n\n"))) return;
  if (await run(btn, "Approving…", () => api("/api/approve", { proposal_id: p.id }))) banner(`Registered ${p.spiffe_id}`, "info");
}

async function revoke(entry, btn) {
  if (!confirm(`Revoke ${entry.spiffe_id}?\n\nThe server will stop issuing SVIDs for it. SVIDs already issued stay valid until they expire.`)) return;
  if (await run(btn, "Revoking…", () => api("/api/revoke", { entry_id: entry.id }))) banner(`Revoked ${entry.spiffe_id}`, "info");
}

$("scan-btn").addEventListener("click", async () => {
  banner(null);
  if (await run($("scan-btn"), "Scanning…", () => api("/api/scan", {}))) {
    $("scan-btn").disabled = false;
    $("scan-btn").textContent = "Scan now";
  }
});
["f-text", "f-kind", "f-status"].forEach((id) => $(id).addEventListener("input", () => state && render()));

api("/api/state").then((s) => { state = s; render(); }).catch((err) => banner(`Could not load the portal state: ${err.message}`));
