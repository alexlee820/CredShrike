"""Self-contained HTML report generator — the run's deliverable artifact.

Snaffler-parser style: one page, standard sections, offline-viewable
(inline CSS, no CDN, no JS dependencies beyond a tiny reveal toggle):

    header:      target / credential / model / budgets / timestamp
    summary:     tiles (files scanned, hits, flagged, findings)
    credentials: AI-confirmed username/password pairs (masked until clicked)
    findings:    full findings table with severity badges + evidence
    scan hits:   every regex hit with masked snippet
    smb files:   directories enumerated + files read (from the audit trail)
    flagged:     files the read gate refused (with reasons)
    ai report:   the model's final markdown report, verbatim
    audit:       every tool call (redacted args, verdicts)

NOTE: the file intentionally CONTAINS the credentials that were found —
that is its purpose. Treat it like a loot file.
"""

from __future__ import annotations

import html
import json
import os
import time
from typing import Optional

SEVERITY_COLORS = {"high": "#ff6b6b", "medium": "#ffb84d", "low": "#4da3ff"}
VERDICT_COLORS = {"allowed": "#43d17c", "capped": "#ffb84d", "flagged": "#ffd166",
                  "refused": "#ff6b6b", "error": "#ff6b6b"}


def _esc(value) -> str:
    return html.escape(str(value if value is not None else ""))


def _esc_cap(value, cap: int = 160) -> str:
    text = _esc(value)
    if len(text) > cap:
        return text[:cap] + "…"
    return text


def _secret_cell(value: Optional[str]) -> str:
    if not value:
        return "<td class='dim'>—</td>"
    if len(value) > 120:   # long secret: masked view shows head + count
        masked = value[:2] + "•" * 10 + f" ({len(value)} chars)"
    else:
        masked = value[0] + "•" * max(len(value) - 1, 3) if len(value) > 1 else "•••"
    return (f"<td><span class='secret' data-real='{_esc(value)}'>{_esc(masked)}</span>"
            f" <button class='reveal' onclick='reveal(this)'>show</button></td>")


def _read_audit(audit_path: str) -> list[dict]:
    entries = []
    if audit_path and os.path.exists(audit_path):
        with open(audit_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    return entries


def _render_transcript(transcript: list) -> str:
    """Turn the captured loop transcript into HTML turns."""
    if not transcript:
        return "<p class='dim'>no transcript captured</p>"
    turns = []
    turn_no = 0
    for entry in transcript:
        kind = entry.get("kind")
        if kind == "goal":
            turns.append(
                "<div class='turn goal'><div class='who'>You</div>"
                f"<div class='say'>{_esc(entry.get('text', ''))}</div></div>")
        elif kind == "assistant":
            turn_no += 1
            tools = "".join(
                f"<div class='call'>→ {_esc(t['name'])}({_esc(json.dumps(t['input'], ensure_ascii=False, default=str))})</div>"
                for t in entry.get("tools", []))
            say = _esc(entry.get("text", "")) or "<span class='dim'>(no narration)</span>"
            turns.append(
                f"<div class='turn'><div class='who'>AI · turn {turn_no}</div>"
                f"<div class='say'>{say}</div>{tools}</div>")
        elif kind == "tool_results":
            items = " · ".join(
                f"<span class='{'ok' if i['ok'] else 'err'}'>{_esc(i['name'])} "
                f"{'ok' if i['ok'] else 'error'} ({i['chars']}c)</span>"
                for i in entry.get("items", []))
            turns.append(f"<div class='turn results'><div class='who'>results</div>"
                         f"<div class='call'>{items}</div></div>")
    return "\n".join(turns)


def build_report_html(*, context: dict, findings: list[dict], scan_results: list[dict],
                      flagged: list[dict], report_md: str, audit_path: str,
                      redactions: int = 0, extraction_error: str = "",
                      domain_computers: Optional[list] = None,
                      share_inventories: Optional[dict] = None,
                      transcript: Optional[list] = None,
                      debug_results: Optional[list] = None) -> str:
    audit = _read_audit(audit_path)
    reads = [e for e in audit if e.get("tool") == "smb_read_file"]
    listings = [e for e in audit if e.get("tool") == "smb_list_dir"]
    scans = [e for e in audit if e.get("tool") == "smb_scan_share"]
    cred_findings = [f for f in findings if f.get("category") == "credential"
                     and (f.get("secret") or f.get("username"))]
    hits = [m for scan in scan_results for m in scan.get("matches", [])]
    domain_computers = domain_computers or []
    share_inventories = share_inventories or {}
    total_shares = sum(len(v) for v in share_inventories.values())
    stats = {}
    for scan in scan_results:
        for key, value in scan.get("stats", {}).items():
            stats[key] = stats.get(key, 0) + value

    transcript = transcript or []
    debug_results = debug_results or []
    ai_turns = sum(1 for e in transcript if e.get("kind") == "assistant")

    debug_entries = "".join(
        f"<div class='turn'><div class='who'>{_esc(i + 1)}. {_esc(d['tool'])} "
        f"<span class='dim'>({d['chars']} chars)</span></div>"
        f"<div class='mono dim'>{_esc(json.dumps(d['args'], ensure_ascii=False)[:200])}</div>"
        f"<pre class='report'>{_esc_cap(d['content'], 20000)}</pre></div>"
        for i, d in enumerate(debug_results)) or \
        "<p class='dim'>debug mode was off for this run</p>"

    computers_rows = "".join(
        f"<tr><td>{_esc(c.get('cn'))}</td>"
        f"<td class='path'>{_esc(c.get('dns_name'))}</td>"
        f"<td>{_esc(c.get('operating_system'))} {_esc(c.get('os_version'))}</td>"
        f"<td>{'<b class=red>DC</b>' if c.get('is_dc') else '—'}</td>"
        f"<td>{'⛔' if c.get('disabled') else '✓'}</td>"
        f"<td class='dim'>{_esc(c.get('description'))}</td></tr>"
        for c in domain_computers) or \
        "<tr><td colspan='6' class='dim'>domain_list_computers was not called</td></tr>"

    shares_rows = "".join(
        f"<tr><td>{_esc(host)}</td><td><b>{_esc(s.get('name'))}</b></td>"
        f"<td>{_esc(s.get('type_name'))}</td><td class='dim'>{_esc(s.get('remark'))}</td>"
        f"<td>{'yes' if s.get('special') else '—'}</td></tr>"
        for host, shares in share_inventories.items() for s in shares) or \
        "<tr><td colspan='5' class='dim'>no shares were enumerated</td></tr>"

    ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

    def tile(label: str, value) -> str:
        return f"<div class='tile'><b>{value}</b><span>{label}</span></div>"

    creds_rows = "".join(
        f"<tr><td><span class='sev {f['severity']}'>{f['severity']}</span></td>"
        f"<td>{_esc(f.get('username') or '—')}</td>{_secret_cell(f.get('secret'))}"
        f"<td class='path'>{_esc(f.get('host'))}/{_esc(f.get('share'))}/{_esc(f.get('path'))}</td>"
        f"<td class='dim ev'>{_esc_cap(f.get('evidence'))}</td></tr>"
        for f in cred_findings) or "<tr><td colspan='5' class='dim'>none</td></tr>"

    findings_rows = "".join(
        f"<tr><td><span class='sev {f['severity']}'>{f['severity']}</span></td>"
        f"<td>{_esc(f['category'])}</td>"
        f"<td class='path'>{_esc(f.get('host'))}/{_esc(f.get('share'))}/{_esc(f.get('path'))}</td>"
        f"<td>{_esc_cap(f.get('note'))}</td><td class='dim ev'>{_esc_cap(f.get('evidence'))}</td></tr>"
        for f in findings) or "<tr><td colspan='5' class='dim'>none</td></tr>"

    hits_rows = "".join(
        f"<tr><td class='tier {h.get('tier')}'>{_esc(h.get('tier'))}</td>"
        f"<td class='path'>{_esc(h.get('path'))}</td><td>{_esc(h.get('line'))}</td>"
        f"<td>{_esc(h.get('pattern'))}</td><td class='mono'>{_esc(h.get('snippet'))}</td></tr>"
        for h in hits) or "<tr><td colspan='5' class='dim'>no sweep was run</td></tr>"

    read_rows = "".join(
        f"<tr><td class='path'>{_esc(e['args'].get('host'))}/{_esc(e['args'].get('share'))}"
        f"/{_esc(e['args'].get('path'))}</td>"
        f"<td>{_esc(e['args'].get('offset', 0))}+{_esc(e['args'].get('max_bytes', ''))}B</td>"
        f"<td><span class='verdict {e['verdict']}'>{e['verdict']}</span></td>"
        f"<td class='dim'>{e.get('duration_ms', '')} ms</td></tr>"
        for e in reads) or "<tr><td colspan='4' class='dim'>no files were read</td></tr>"

    listing_paths = sorted({f"{e['args'].get('share')}/{e['args'].get('path', '')}".rstrip("/")
                            for e in listings})
    listings_html = "".join(f"<code>{_esc(p)}</code> " for p in listing_paths) or \
        "<span class='dim'>no directories enumerated</span>"

    flagged_rows = "".join(
        f"<tr><td class='path'>{_esc(f.get('host'))}/{_esc(f.get('share'))}/{_esc(f.get('path'))}</td>"
        f"<td>{_esc(f.get('size_bytes') or '—')}</td><td class='dim'>{_esc(f.get('reason'))}</td></tr>"
        for f in flagged) or "<tr><td colspan='3' class='dim'>none</td></tr>"

    audit_rows = "".join(
        f"<tr><td>{_esc(e['tool'])}</td>"
        f"<td class='mono dim'>{_esc(json.dumps(e['args'], ensure_ascii=False)[:160])}</td>"
        f"<td><span class='verdict {e['verdict']}'>{e['verdict']}</span></td>"
        f"<td>{e.get('result_chars', '')}</td><td class='dim'>{e.get('duration_ms', '')} ms</td></tr>"
        for e in audit)

    extraction_note = (f"<p class='warn'>⚠ findings extraction failed: "
                       f"{_esc(extraction_error)} — sections below rely on the raw "
                       f"AI report only.</p>" if extraction_error else "")

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>smbenum report — {_esc(context.get('principal'))} @ {_esc(', '.join(context.get('scope') or []))}</title>
<style>
  :root {{ --bg:#101418; --panel:#171d24; --line:#26303a; --fg:#cdd6e0; --dim:#7d8a99; --acc:#4da3ff; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; font:14px/1.5 "Segoe UI",system-ui,sans-serif; background:var(--bg); color:var(--fg); }}
  .wrap {{ max-width:1200px; margin:0 auto; padding:24px 20px; }}
  h1 {{ font-size:20px; margin:0; }} h2 {{ font-size:14px; color:var(--acc);
       text-transform:uppercase; letter-spacing:1px; border-bottom:1px solid var(--line);
       padding-bottom:6px; margin:28px 0 10px; }}
  .meta {{ display:flex; flex-wrap:wrap; gap:6px 22px; color:var(--dim); font-size:12px; margin-top:8px; }}
  .meta b {{ color:var(--fg); }}
  .tiles {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:10px; margin-top:16px; }}
  .tile {{ background:var(--panel); border:1px solid var(--line); border-radius:8px;
          padding:12px; text-align:center; }} .tile b {{ font-size:22px; display:block; }}
  .tile span {{ color:var(--dim); font-size:11px; text-transform:uppercase; }}
  table {{ width:100%; border-collapse:collapse; background:var(--panel);
          border:1px solid var(--line); border-radius:8px; overflow:hidden; }}
  th, td {{ padding:7px 10px; text-align:left; border-bottom:1px solid var(--line); font-size:13px; }}
  th {{ color:var(--dim); font-size:11px; text-transform:uppercase; letter-spacing:.5px;
       background:#12171d; }}
  td, th, pre, .path, .mono, .secret, .say, .call, .ev {{
      overflow-wrap:anywhere; word-break:break-word; max-width:520px; }}
  tr:last-child td {{ border-bottom:0; }}
  .dim {{ color:var(--dim); }} .mono {{ font-family:Consolas,monospace; font-size:12px; }}
  .path {{ font-family:Consolas,monospace; font-size:12px; color:#b9d4f0; }}
  .ev {{ font-size:11px; max-width:260px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
  .sev {{ padding:1px 8px; border-radius:9px; font-size:11px; font-weight:600; color:#101418; }}
  .sev.high {{ background:#ff6b6b; }} .sev.medium {{ background:#ffb84d; }}
  .sev.low {{ background:#4da3ff; }}
  .verdict {{ font-size:11px; padding:1px 7px; border-radius:8px; }}
  .verdict.allowed {{ background:#16351f; color:#43d17c; }}
  .verdict.capped {{ background:#3a2f16; color:#ffb84d; }}
  .verdict.flagged {{ background:#3a3a16; color:#ffd166; }}
  .verdict.refused, .verdict.error {{ background:#3d1c1c; color:#ff6b6b; }}
  .tier {{ font-size:11px; font-weight:700; }} .tier.red {{ color:#ff6b6b; }}
  .tier.yellow {{ color:#ffd166; }}
  .red {{ color:#ff6b6b; }}
  .secret {{ font-family:Consolas,monospace; }}
  .reveal {{ background:#22303d; color:var(--fg); border:0; border-radius:4px;
            font-size:10px; padding:1px 6px; cursor:pointer; }}
  .warn {{ color:#ffb84d; font-size:13px; }}
  pre.report {{ background:#0b0f13; border:1px solid var(--line); border-radius:8px;
               padding:14px; white-space:pre-wrap; font:13px/1.6 Consolas,monospace; }}
  footer {{ color:var(--dim); font-size:11px; margin-top:30px; border-top:1px solid var(--line);
           padding-top:10px; }}
  .tabs {{ display:flex; flex-wrap:wrap; gap:4px; position:sticky; top:0; z-index:5;
          background:var(--bg); padding:12px 0 8px; border-bottom:1px solid var(--line); }}
  .tab {{ background:var(--panel); color:var(--dim); border:1px solid var(--line);
         border-radius:6px; padding:6px 13px; cursor:pointer; font:inherit; font-size:13px; }}
  .tab:hover {{ color:var(--fg); }}
  .tab.active {{ color:#08121d; background:var(--acc); border-color:var(--acc); font-weight:600; }}
  .tab .badge {{ background:#0d1117; border-radius:9px; font-size:10px; padding:1px 7px;
                margin-left:5px; color:var(--fg); }}
  .tab.active .badge {{ background:rgba(0,0,0,.28); color:#08121d; }}
  .tab-panel {{ display:none; padding-top:14px; }}
  .tab-panel.active {{ display:block; }}
  .tab-panel h2 {{ margin-top:10px; }}
  .turn {{ border-left:2px solid var(--line); padding:4px 14px; margin:12px 0; }}
  .turn.goal {{ border-left-color:var(--acc); }}
  .turn.results {{ border-left-color:#2c3a2c; }}
  .who {{ color:var(--dim); font-size:11px; text-transform:uppercase; letter-spacing:.5px; }}
  .say {{ white-space:pre-wrap; margin:4px 0; }}
  .call {{ font-family:Consolas,monospace; font-size:12px; color:var(--acc); margin:2px 0; }}
  .call .ok {{ color:#43d17c; }} .call .err {{ color:#ff6b6b; }}
  @media print {{
    .tabs {{ display:none; }}
    .tab-panel {{ display:block !important; page-break-before:always; }}
    .tab-panel:first-of-type {{ page-break-before:auto; }}
  }}
</style></head><body><div class="wrap">
<h1>smbenum — SMB enumeration report</h1>
<div class="meta">
  <span>target <b>{_esc(', '.join(context.get('scope') or ['unrestricted']))}</b></span>
  <span>credential <b>{_esc(context.get('principal'))}</b> ({_esc(context.get('auth_type'))})</span>
  <span>model <b>{_esc(context.get('model'))}</b></span>
  <span>endpoint <b>{_esc(context.get('endpoint'))}</b></span>
  <span>generated <b>{ts}</b></span>
  <span>audit <b>{_esc(audit_path)}</b></span>
  <span>redactions applied <b>{redactions}</b></span>
</div>

<nav class="tabs">
  <button class="tab active" data-tab="overview">Overview</button>
  <button class="tab" data-tab="creds">Credentials<span class="badge">{len(cred_findings)}</span></button>
  <button class="tab" data-tab="findings">Findings<span class="badge">{len(findings)}</span></button>
  <button class="tab" data-tab="hits">Sweep hits<span class="badge">{len(hits)}</span></button>
  <button class="tab" data-tab="computers">Computers<span class="badge">{len(domain_computers)}</span></button>
  <button class="tab" data-tab="shares">Shares<span class="badge">{total_shares}</span></button>
  <button class="tab" data-tab="smb">SMB activity<span class="badge">{len(reads) + len(flagged)}</span></button>
  <button class="tab" data-tab="aireport">AI report</button>
  <button class="tab" data-tab="transcript">Transcript<span class="badge">{ai_turns}</span></button>
  {"<button class=\"tab\" data-tab=\"debug\">Debug<span class=\"badge\">" + str(len(debug_results)) + "</span></button>" if debug_results else ""}
  <button class="tab" data-tab="audit">Audit<span class="badge">{len(audit)}</span></button>
</nav>

<div class="tab-panel active" id="overview">
  <div class="tiles">
    {tile('domain computers', len(domain_computers))}
    {tile('shares', total_shares)}
    {tile('files scanned', stats.get('files_scanned', len(reads)))}
    {tile('sweep hits', len(hits))}
    {tile('flagged', len(flagged))}
    {tile('AI findings', len(findings))}
    {tile('credentials', len(cred_findings))}
    {tile('tool calls', len(audit))}
  </div>
  {extraction_note}
</div>

<div class="tab-panel" id="creds">
  <h2>Credentials (AI-confirmed — click "show" to reveal)</h2>
  <table><tr><th>severity</th><th>username</th><th>secret</th><th>location</th><th>evidence</th></tr>
  {creds_rows}</table>
</div>

<div class="tab-panel" id="findings">
  <h2>All findings</h2>
  <table><tr><th>severity</th><th>category</th><th>location</th><th>note</th><th>evidence</th></tr>
  {findings_rows}</table>
</div>

<div class="tab-panel" id="hits">
  <h2>Sweep hits (regex, secrets masked)</h2>
  <table><tr><th>tier</th><th>path</th><th>line</th><th>pattern</th><th>snippet</th></tr>
  {hits_rows}</table>
</div>

<div class="tab-panel" id="computers">
  <h2>Domain computers ({len(domain_computers)})</h2>
  <table><tr><th>name</th><th>dns name</th><th>operating system</th><th>role</th>
  <th>enabled</th><th>description</th></tr>
  {computers_rows}</table>
</div>

<div class="tab-panel" id="shares">
  <h2>Share inventory ({total_shares} shares on {len(share_inventories)} host{'s' if len(share_inventories) != 1 else ''})</h2>
  <table><tr><th>host</th><th>share</th><th>type</th><th>remark</th><th>special</th></tr>
  {shares_rows}</table>
</div>

<div class="tab-panel" id="smb">
  <h2>Files read ({len(reads)})</h2>
  <table><tr><th>file read</th><th>range</th><th>verdict</th><th>duration</th></tr>{read_rows}</table>
  <h2>Flagged files (not read, {len(flagged)})</h2>
  <table><tr><th>path</th><th>size</th><th>reason</th></tr>{flagged_rows}</table>
  <h2>Directories enumerated</h2>
  <p>{listings_html}</p>
</div>

<div class="tab-panel" id="aireport">
  <h2>AI final report (verbatim)</h2>
  <pre class="report">{_esc(report_md) or '—'}</pre>
</div>

<div class="tab-panel" id="transcript">
  <h2>AI transcript — every response, in order</h2>
  {_render_transcript(transcript)}
</div>

{("<div class='tab-panel' id='debug'><h2>Debug — full tool results exactly as "
  "the model received them</h2>" + debug_entries + "</div>") if debug_results else ""}

<div class="tab-panel" id="audit">
  <h2>Audit trail ({len(audit)} calls)</h2>
  <table><tr><th>tool</th><th>args</th><th>verdict</th><th>chars</th><th>ms</th></tr>{audit_rows}</table>
</div>

<footer>Generated by smbenum. This artifact contains discovered credentials by
design — store and share it like a loot file (it is already excluded from git).</footer>
<script>
function reveal(btn) {{
  const s = btn.previousElementSibling;
  const real = s.getAttribute('data-real');
  if (btn.textContent === 'show') {{ s.textContent = real; btn.textContent = 'hide'; }}
  else {{ btn.textContent = 'show'; s.textContent = real[0] + '•'.repeat(Math.max(real.length - 1, 3)); }}
}}
function activate(id) {{
  document.querySelectorAll('.tab').forEach(b =>
    b.classList.toggle('active', b.dataset.tab === id));
  document.querySelectorAll('.tab-panel').forEach(p =>
    p.classList.toggle('active', p.id === id));
  if (location.hash !== '#' + id) history.replaceState(null, '', '#' + id);
}}
document.querySelectorAll('.tab').forEach(b =>
  b.addEventListener('click', () => activate(b.dataset.tab)));
const startTab = location.hash.replace('#', '');
if (startTab && document.getElementById(startTab)) activate(startTab);
</script>
</div></body></html>"""


def write_report(path: str, **kwargs) -> str:
    html_text = build_report_html(**kwargs)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html_text)
    return path


# --------------------------------------------------------------------------- #
# domain-sweep index (full-domain preset)
# --------------------------------------------------------------------------- #
def build_domain_index_html(*, context: dict, hosts: list, merged: dict,
                            computers: list) -> str:
    ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    status_colors = {"done": "#43d17c", "unreachable": "#7d8a99",
                     "error": "#ff6b6b", "skipped-budget": "#ffb84d"}

    host_options = "".join(f'<option value="{_esc(h["host"])}">{_esc(h["host"])}</option>'
                           for h in hosts)

    def _link_cell(h: dict) -> str:
        if not h.get("html"):
            return "<td class='dim'>—</td>"
        return (f"<td><a href='{_esc(h['html'])}'>"
                f"{_esc(h['html'])}</a></td>")

    matrix_rows = "".join(
        f"<tr><td class='path'>{_esc(h['host'])}</td>"
        f"<td><b style='color:{status_colors.get(h['status'], '#7d8a99')}'>{_esc(h['status'])}</b></td>"
        f"<td>{len(h.get('shares', []))}</td><td>{h.get('tool_calls', 0)}</td>"
        f"<td>{(h.get('bytes_read', 0) / 1024):.0f}K</td>"
        f"<td>{len(h.get('findings', []))}</td>"
        f"{_link_cell(h)}"
        f"<td class='dim'>{_esc_cap(h.get('error', '') or '', 120)}</td></tr>"
        for h in hosts)

    cred_rows = ""
    for f in merged.get("credentials", []):
        locations = "; ".join(f"{_esc(l['host'])}/{_esc(l['share'])}/{_esc(l['path'])}"
                              for l in f.get("locations", []))
        hosts_attr = " ".join(sorted({l["host"] for l in f.get("locations", [])}))
        cred_rows += (f"<tr data-host=\"{_esc(hosts_attr)}\">"
                      f"<td><span class='sev {f['severity']}'>{f['severity']}</span></td>"
                      f"<td>{_esc(f.get('username') or '—')}</td>{_secret_cell(f.get('secret'))}"
                      f"<td class='path'>{locations}</td>"
                      f"<td class='dim ev'>{_esc(f.get('evidence', ''))}</td></tr>")
    cred_rows = cred_rows or "<tr><td colspan='5' class='dim'>none</td></tr>"

    other_rows = "".join(
        f"<tr data-host=\"{_esc(f['locations'][0]['host'])}\">"
        f"<td><span class='sev {f['severity']}'>{f['severity']}</span></td>"
        f"<td>{_esc(f['category'])}</td>"
        f"<td class='path'>{_esc(f['locations'][0]['host'])}/{_esc(f['locations'][0]['share'])}"
        f"/{_esc(f['locations'][0]['path'])}</td>"
        f"<td>{_esc(f.get('note', ''))}</td></tr>"
        for f in merged.get("other", [])) or \
        "<tr><td colspan='4' class='dim'>none</td></tr>"

    def _summary_line(h: dict) -> str:
        link = (f" · <a href='{_esc(h['html'])}'>full report</a>"
                if h.get("html") else "")
        return f"{_esc(h['host'])} — {_esc(h['status'])}{link}"

    per_host_reports = "".join(
        f"<details data-host=\"{_esc(h['host'])}\"><summary>{_summary_line(h)}</summary>"
        f"<pre class='report'>{_esc(h.get('report_md', '') or h.get('error', '') or '—')}</pre></details>"
        for h in hosts)

    done = sum(1 for h in hosts if h["status"] == "done")
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>smbenum domain sweep — {_esc(context.get('principal'))} ({done}/{len(hosts)} hosts)</title>
<style>
  :root {{ --bg:#101418; --panel:#171d24; --line:#26303a; --fg:#cdd6e0; --dim:#7d8a99; --acc:#4da3ff; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; font:14px/1.5 "Segoe UI",system-ui,sans-serif; background:var(--bg); color:var(--fg); }}
  .wrap {{ max-width:1300px; margin:0 auto; padding:24px 20px; }}
  h1 {{ font-size:20px; margin:0; }} h2 {{ font-size:14px; color:var(--acc);
       text-transform:uppercase; letter-spacing:1px; border-bottom:1px solid var(--line);
       padding-bottom:6px; margin:28px 0 10px; }}
  .meta {{ display:flex; flex-wrap:wrap; gap:6px 22px; color:var(--dim); font-size:12px; margin-top:8px; }}
  .meta b {{ color:var(--fg); }}
  select {{ background:#0d1117; color:var(--fg); border:1px solid var(--line);
           border-radius:6px; padding:6px 10px; font:inherit; margin:10px 0; }}
  table {{ width:100%; border-collapse:collapse; background:var(--panel);
          border:1px solid var(--line); border-radius:8px; overflow:hidden; }}
  th, td {{ padding:7px 10px; text-align:left; border-bottom:1px solid var(--line); font-size:13px; }}
  th {{ color:var(--dim); font-size:11px; text-transform:uppercase; background:#12171d; }}
  tr:last-child td {{ border-bottom:0; }}
  .dim {{ color:var(--dim); }} .path {{ font-family:Consolas,monospace; font-size:12px; color:#b9d4f0; }}
  .ev {{ font-size:11px; max-width:280px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
  .sev {{ padding:1px 8px; border-radius:9px; font-size:11px; font-weight:600; color:#101418; }}
  .sev.high {{ background:#ff6b6b; }} .sev.medium {{ background:#ffb84d; }} .sev.low {{ background:#4da3ff; }}
  .secret {{ font-family:Consolas,monospace; }}
  .reveal {{ background:#22303d; color:var(--fg); border:0; border-radius:4px;
            font-size:10px; padding:1px 6px; cursor:pointer; }}
  pre.report {{ background:#0b0f13; border:1px solid var(--line); border-radius:8px;
               padding:14px; white-space:pre-wrap; font:13px/1.6 Consolas,monospace; }}
  details {{ margin:10px 0; }} summary {{ cursor:pointer; color:var(--acc); }}
  footer {{ color:var(--dim); font-size:11px; margin-top:30px; border-top:1px solid var(--line); padding-top:10px; }}
</style></head><body><div class="wrap">
<h1>smbenum — domain sweep report</h1>
<div class="meta">
  <span>credential <b>{_esc(context.get('principal'))}</b> ({_esc(context.get('auth_type'))})</span>
  <span>model <b>{_esc(context.get('model'))}</b></span>
  <span>endpoint <b>{_esc(context.get('endpoint'))}</b></span>
  <span>generated <b>{ts}</b></span>
  <span>computers in domain <b>{len(computers)}</b></span>
  <span>hosts swept <b>{done}/{len(hosts)}</b></span>
</div>

<h2>Coverage matrix</h2>
<table><tr><th>host</th><th>status</th><th>shares</th><th>tool calls</th><th>read</th>
<th>findings</th><th>full report</th><th>error</th></tr>
{matrix_rows}</table>

<h2>Credentials — merged across hosts (identical user/secret collapsed)</h2>
<label style="font-size:12px;color:var(--dim)">filter by host:</label>
<select id="hostFilter" onchange="filterHost(this.value)">
  <option value="">all hosts</option>{host_options}
</select>
<table id="credTable"><tr><th>severity</th><th>username</th><th>secret</th>
<th>locations</th><th>evidence</th></tr>{cred_rows}</table>

<h2>Other findings</h2>
<table><tr><th>severity</th><th>category</th><th>location</th><th>note</th></tr>{other_rows}</table>

<h2>Per-host AI reports</h2>
{per_host_reports}

<footer>Generated by smbenum full-domain sweep. Per-host details in the linked
reports; this artifact contains credentials by design.</footer>
<script>
function reveal(btn) {{
  const s = btn.previousElementSibling; const real = s.getAttribute('data-real');
  if (btn.textContent === 'show') {{ s.textContent = real; btn.textContent = 'hide'; }}
  else {{ btn.textContent = 'show'; s.textContent = real[0] + '•'.repeat(Math.max(real.length - 1, 3)); }}
}}
function filterHost(host) {{
  document.querySelectorAll('[data-host]').forEach(row => {{
    if (!host || (row.getAttribute('data-host') || '').split(' ').includes(host))
      row.style.display = '';
    else row.style.display = 'none';
  }});
}}
</script>
</div></body></html>"""


def write_domain_index(path: str, **kwargs) -> str:
    html_text = build_domain_index_html(**kwargs)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html_text)
    return path
