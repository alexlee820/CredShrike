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


def _secret_cell(value: Optional[str]) -> str:
    if not value:
        return "<td class='dim'>—</td>"
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


def build_report_html(*, context: dict, findings: list[dict], scan_results: list[dict],
                      flagged: list[dict], report_md: str, audit_path: str,
                      redactions: int = 0, extraction_error: str = "") -> str:
    audit = _read_audit(audit_path)
    reads = [e for e in audit if e.get("tool") == "smb_read_file"]
    listings = [e for e in audit if e.get("tool") == "smb_list_dir"]
    scans = [e for e in audit if e.get("tool") == "smb_scan_share"]
    cred_findings = [f for f in findings if f.get("category") == "credential"
                     and (f.get("secret") or f.get("username"))]
    hits = [m for scan in scan_results for m in scan.get("matches", [])]
    stats = {}
    for scan in scan_results:
        for key, value in scan.get("stats", {}).items():
            stats[key] = stats.get(key, 0) + value

    ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

    def tile(label: str, value) -> str:
        return f"<div class='tile'><b>{value}</b><span>{label}</span></div>"

    creds_rows = "".join(
        f"<tr><td><span class='sev {f['severity']}'>{f['severity']}</span></td>"
        f"<td>{_esc(f.get('username') or '—')}</td>{_secret_cell(f.get('secret'))}"
        f"<td class='path'>{_esc(f.get('host'))}/{_esc(f.get('share'))}/{_esc(f.get('path'))}</td>"
        f"<td class='dim ev'>{_esc(f.get('evidence'))}</td></tr>"
        for f in cred_findings) or "<tr><td colspan='5' class='dim'>none</td></tr>"

    findings_rows = "".join(
        f"<tr><td><span class='sev {f['severity']}'>{f['severity']}</span></td>"
        f"<td>{_esc(f['category'])}</td>"
        f"<td class='path'>{_esc(f.get('host'))}/{_esc(f.get('share'))}/{_esc(f.get('path'))}</td>"
        f"<td>{_esc(f.get('note'))}</td><td class='dim ev'>{_esc(f.get('evidence'))}</td></tr>"
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
  .secret {{ font-family:Consolas,monospace; }}
  .reveal {{ background:#22303d; color:var(--fg); border:0; border-radius:4px;
            font-size:10px; padding:1px 6px; cursor:pointer; }}
  .warn {{ color:#ffb84d; font-size:13px; }}
  pre.report {{ background:#0b0f13; border:1px solid var(--line); border-radius:8px;
               padding:14px; white-space:pre-wrap; font:13px/1.6 Consolas,monospace; }}
  footer {{ color:var(--dim); font-size:11px; margin-top:30px; border-top:1px solid var(--line);
           padding-top:10px; }}
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

<div class="tiles">
  {tile('files scanned', stats.get('files_scanned', len(reads)))}
  {tile('sweep hits', len(hits))}
  {tile('flagged', len(flagged))}
  {tile('AI findings', len(findings))}
  {tile('credentials', len(cred_findings))}
  {tile('tool calls', len(audit))}
</div>
{extraction_note}

<h2>Credentials (AI-confirmed — click "show" to reveal)</h2>
<table><tr><th>severity</th><th>username</th><th>secret</th><th>location</th><th>evidence</th></tr>
{creds_rows}</table>

<h2>All findings</h2>
<table><tr><th>severity</th><th>category</th><th>location</th><th>note</th><th>evidence</th></tr>
{findings_rows}</table>

<h2>Sweep hits (regex, secrets masked)</h2>
<table><tr><th>tier</th><th>path</th><th>line</th><th>pattern</th><th>snippet</th></tr>
{hits_rows}</table>

<h2>SMB activity</h2>
<p style="font-size:12px;color:var(--dim)">directories enumerated:</p>
<p>{listings_html}</p>
<table><tr><th>file read</th><th>range</th><th>verdict</th><th>duration</th></tr>{read_rows}</table>
<h2>Flagged files (not read)</h2>
<table><tr><th>path</th><th>size</th><th>reason</th></tr>{flagged_rows}</table>

<h2>AI final report (verbatim)</h2>
<pre class="report">{_esc(report_md) or '—'}</pre>

<h2>Audit trail ({len(audit)} calls)</h2>
<table><tr><th>tool</th><th>args</th><th>verdict</th><th>chars</th><th>ms</th></tr>{audit_rows}</table>

<footer>Generated by smbenum. This artifact contains discovered credentials by
design — store and share it like a loot file (it is already excluded from git).</footer>
<script>
function reveal(btn) {{
  const s = btn.previousElementSibling;
  const real = s.getAttribute('data-real');
  if (btn.textContent === 'show') {{ s.textContent = real; btn.textContent = 'hide'; }}
  else {{ btn.textContent = 'show'; s.textContent = real[0] + '•'.repeat(Math.max(real.length - 1, 3)); }}
}}
</script>
</div></body></html>"""


def write_report(path: str, **kwargs) -> str:
    html_text = build_report_html(**kwargs)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html_text)
    return path
