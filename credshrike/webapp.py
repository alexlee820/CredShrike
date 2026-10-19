"""Local web UI: initialize agent runs, watch live progress, read reports.

Design:
- Serves a single static page (CredShrike/web/index.html) that talks to a small
  JSON API and polls — no websockets, no build tooling.
- Runs an AgentSession + AgentLoop on a background thread per run; echo lines
  and scanner progress events land in an in-memory ring buffer the page polls.
- Binds 127.0.0.1 ONLY. The form collects real credentials — this UI is for
  the operator's own machine; do not expose it over the network.
- The LLM client factory is swappable (``_client_factory``) so tests inject a
  scripted fake without any API key.
"""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from pathlib import Path

from flask import Flask, Response, jsonify, request, send_from_directory

from .agent.audit import AuditLog
from .agent.loop import AgentLoop
from .agent.session import AgentSession
from .config import Policy
from .credentials import Credential
from .agent.cli_agent import SNAFFLER_PRESET, FULL_PRESET

WEB_DIR = Path(__file__).parent / "web"

app = Flask(__name__)

# swap in tests: webapp._client_factory = lambda: FakeClient()
_client_factory = None


def _build_client(params: dict):
    """Anthropic SDK client, optionally pointed at an Anthropic-compatible
    endpoint (GLM / DeepSeek / ...) via base_url + api_key from the form."""
    from anthropic import Anthropic
    kwargs = {}
    if params.get("api_base_url"):
        kwargs["base_url"] = params["api_base_url"]
    if params.get("api_key"):
        kwargs["api_key"] = params["api_key"]
    return Anthropic(**kwargs)


class RunState:
    def __init__(self, run_id: str, params: dict):
        self.id = run_id
        self.params = params
        self.status = "starting"     # starting|running|done|error|stopped
        self.lines: list[str] = []
        self.report: str = ""
        self.report_html_path = ""
        self.error: str = ""
        self.created = time.time()
        self.audit_path = ""
        self.session: AgentSession | None = None
        self.loop: AgentLoop | None = None
        self.lock = threading.Lock()

    def push(self, line: str) -> None:
        # cap stored line length: debug-mode tool results can be 40K+ chars
        # per line — raw storage would blow up the polling payload and the
        # browser render
        if len(line) > 4000:
            line = line[:4000] + " …[line truncated — full copy in the report's Debug tab]"
        with self.lock:
            self.lines.append(line)
            if len(self.lines) > 5000:
                del self.lines[:1000]

    def public(self) -> dict:
        session = self.session
        return {
            "id": self.id, "status": self.status, "created": self.created,
            "lines": self.lines[-300:],
            "report": self.report, "error": self.error,
            "report_html": self.report_html_path or None,
            "audit_path": self.audit_path,
            "budget": session.budget.snapshot() if session else None,
            "flagged": session.flagged_files if session else [],
            "redactions": session.redactions_applied if session else 0,
            "context": ({"principal": session.credential.redacted()["principal"],
                         "auth_type": session.credential.redacted()["auth_type"],
                         "scope": session.allowed_hosts,
                         "read_gate": session.policy.read_gate,
                         "domain_source": session.domain_source,
                         "dc": session.dc,
                         "model": session.policy.model,
                         "endpoint": session.policy.api_base_url or "api.anthropic.com",
                         "thinking": session.policy.thinking_mode,
                         "debug": session.policy.debug} if session else None),
            "context_tokens": (self.loop.context_tokens if self.loop else 0),
            "context_limit": (session.policy.context_token_limit or 0 if session else 0),
        }


RUNS: dict[str, RunState] = {}


# --------------------------------------------------------------------------- #
# run lifecycle (background thread)
# --------------------------------------------------------------------------- #
def _start_run(params: dict) -> str:
    run_id = uuid.uuid4().hex[:12]
    state = RunState(run_id, params)
    RUNS[run_id] = state
    threading.Thread(target=_execute_run, args=(state,), daemon=True).start()
    return run_id


def _execute_run(state: RunState) -> None:
    try:
        state.status = "running"
        params = state.params

        credential = Credential.from_profile(_auth_from_params(params))
        credential.validate()
        policy = Policy.load(params.get("policy_path") or None)
        _apply_policy_overrides(policy, params)

        # default preset: bare runs (no preset AND no goal) → full-domain sweep
        effective_preset = params.get("preset") or \
            ("" if params.get("goal") else "full-domain")
        if effective_preset == "full-domain":
            from .agent.orchestrator import run_domain_sweep
            summary = run_domain_sweep(
                credential=credential, policy=policy,
                audit_dir=params.get("audit_dir") or "runs",
                dc=params.get("dc") or "",
                domain_source=params.get("domain_source") or "auto",
                computers_filter=params.get("computers_filter") or "",
                max_hosts=int(params["max_hosts"]) if params.get("max_hosts") else None,
                client_factory=lambda: (_client_factory() if _client_factory
                                        else _build_client(params)),
                echo=state.push)
            done = sum(1 for h in summary["hosts"] if h["status"] == "done")
            state.report = (f"Domain sweep: {done}/{len(summary['hosts'])} hosts swept, "
                            f"{len(summary['merged']['credentials'])} unique credential(s). "
                            f"Index report: {summary['index_html']}")
            state.report_html_path = summary["index_html"]
            state.audit_path = summary["run_dir"]
            state.status = "done"
            return

        audit = AuditLog.new_run(params.get("audit_dir") or "runs")
        state.audit_path = audit.path
        hosts = [h.strip() for h in (params.get("host") or "").split(",") if h.strip()]
        session = AgentSession(credential, policy, audit, hosts=hosts,
                               dc=params.get("dc") or "",
                               domain_source=params.get("domain_source") or "auto")
        session.event_hook = lambda kind, data: state.push(_fmt_event(kind, data))
        state.session = session

        client = _client_factory() if _client_factory else _build_client(params)
        loop = AgentLoop(client, session, policy, audit,
                         echo=lambda line: state.push(line))
        state.loop = loop

        goal = params.get("goal") or ""
        preset = params.get("preset") or ""
        if preset == "snaffler" and not goal:
            goal = SNAFFLER_PRESET
        elif preset == "full" and not goal:
            goal = FULL_PRESET
        if not goal:
            raise ValueError("no goal or preset given")
        state.report = loop.run(goal)
        state.report_html_path = _emit_report(loop, session, policy, audit, client,
                                              state.report)
        state.status = "stopped" if loop.stop_requested else "done"
    except Exception as exc:  # noqa: BLE001 — surface to the UI
        state.error = f"{type(exc).__name__}: {exc}"
        state.status = "error"
    finally:
        if state.session is not None:
            try:
                state.session.close()
            except Exception:  # noqa: BLE001
                pass


def _emit_report(loop, session, policy, audit, client, report_md: str) -> str:
    """Build the standalone HTML report next to this run's audit log."""
    from pathlib import Path
    from .agent.findings import extract_findings
    findings, extraction_error = [], ""
    try:
        findings = extract_findings(client, policy, loop.messages)
    except Exception as exc:  # noqa: BLE001 - report must still build
        extraction_error = f"{type(exc).__name__}: {exc}"
    from .report import write_report
    red = session.credential.redacted()
    path = str(Path(audit.path).with_suffix(".report.html"))
    write_report(path,
                 context={"principal": red["principal"], "auth_type": red["auth_type"],
                          "scope": session.allowed_hosts, "model": policy.model,
                          "endpoint": policy.api_base_url or "api.anthropic.com"},
                 findings=findings, scan_results=session.scan_results,
                 flagged=session.flagged_files, report_md=report_md,
                 audit_path=audit.path, redactions=session.redactions_applied,
                 extraction_error=extraction_error,
                 domain_computers=session.domain_computers,
                 share_inventories=session.share_inventories,
                 transcript=loop.transcript,
                 debug_results=session.debug_results if session.policy.debug else [])
    return path


def _fmt_event(kind: str, data: dict) -> str:
    if kind == "walk":
        return f"  ⋮ walk {data.get('path') or '/'}"
    if kind == "scan":
        return f"  ⋮ scan [{data.get('tier')}] {data.get('path')} ({data.get('size')} B)"
    if kind == "hit":
        return f"  ★ HIT {data.get('path')} [{data.get('pattern')}]"
    if kind == "file_hit":
        return f"  ★ {data.get('hits')} hit(s) in {data.get('path')}"
    if kind == "done":
        return (f"  ⋮ sweep done: {data.get('matches_total')} match(es), "
                f"truncated={data.get('truncated')}")
    if kind == "walk_error" or kind == "read_error":
        return f"  ! {kind}: {data.get('path')} — {data.get('error')}"
    return f"  ⋮ {kind} {json.dumps(data, ensure_ascii=False)[:160]}"


def _auth_from_params(params: dict) -> dict:
    return {"auth_type": params.get("auth_type", "password"),
            "username": params.get("username", ""),
            "domain": params.get("domain", ""),
            "password": params.get("password", ""),
            "hashes": params.get("hashes", ""),
            "aes_key": params.get("aes_key", ""),
            "ticket": params.get("ticket", ""),
            "kdc": params.get("kdc", "")}


def _apply_policy_overrides(policy: Policy, params: dict) -> None:
    if params.get("model"):
        policy.model = params["model"]
    if params.get("read_gate"):
        policy.read_gate = params["read_gate"]
    if params.get("max_read_tokens"):
        policy.max_read_tokens = int(params["max_read_tokens"])
    if params.get("flag_oversize_mb"):
        policy.flag_oversize_bytes = int(float(params["flag_oversize_mb"]) * 1024 * 1024)
    if params.get("redact"):
        policy.redact_literals = [w.strip() for w in params["redact"].split(",") if w.strip()]
    if params.get("redact_patterns"):
        policy.redact_patterns = list(params["redact_patterns"])
    if params.get("scan_patterns") and isinstance(params["scan_patterns"], dict):
        policy.scan_extra_patterns.update(params["scan_patterns"])
    if params.get("api_base_url"):
        policy.api_base_url = params["api_base_url"]
    if params.get("api_key"):
        policy.api_key = params["api_key"]
    if params.get("thinking_mode"):
        policy.thinking_mode = params["thinking_mode"]
    elif params.get("api_base_url"):
        # adaptive thinking is Anthropic-specific; default off off-API
        policy.thinking_mode = "off"
    if params.get("debug"):
        policy.debug = True
    if params.get("context_limit"):
        policy.context_token_limit = int(params["context_limit"])


# --------------------------------------------------------------------------- #
# routes
# --------------------------------------------------------------------------- #
@app.route("/")
def index():
    return send_from_directory(WEB_DIR, "index.html")


@app.route("/api/runs", methods=["POST"])
def create_run():
    params = request.get_json(force=True, silent=True) or {}
    run_id = _start_run(params)
    return jsonify({"id": run_id})


@app.route("/api/runs", methods=["GET"])
def list_runs():
    return jsonify([{"id": r.id, "status": r.status, "created": r.created}
                    for r in reversed(list(RUNS.values()))])


@app.route("/api/runs/<run_id>", methods=["GET"])
def get_run(run_id):
    state = RUNS.get(run_id)
    if state is None:
        return jsonify({"error": "unknown run"}), 404
    return jsonify(state.public())


@app.route("/api/runs/<run_id>/goal", methods=["POST"])
def followup_goal(run_id):
    state = RUNS.get(run_id)
    if state is None:
        return jsonify({"error": "unknown run"}), 404
    if state.status not in ("done", "stopped"):
        return jsonify({"error": f"run is {state.status}"}), 409
    body = request.get_json(force=True, silent=True) or {}
    goal = body.get("goal", "")
    if not goal:
        return jsonify({"error": "goal required"}), 400

    def _run():
        try:
            state.status = "running"
            state.report = state.loop.run(goal)
            session = state.session
            state.report_html_path = _emit_report(
                state.loop, session, session.policy,
                session.audit, _client_factory() if _client_factory
                else _build_client(state.params), state.report)
            state.status = "stopped" if state.loop.stop_requested else "done"
        except Exception as exc:  # noqa: BLE001
            state.error = f"{type(exc).__name__}: {exc}"
            state.status = "error"

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"ok": True})


@app.route("/api/runs/<run_id>/stop", methods=["POST"])
def stop_run(run_id):
    state = RUNS.get(run_id)
    if state is None:
        return jsonify({"error": "unknown run"}), 404
    if state.loop is not None:
        state.loop.stop_requested = True
    return jsonify({"ok": True})


@app.route("/api/runs/<run_id>/report_html")
def report_html(run_id):
    state = RUNS.get(run_id)
    if state is None or not state.report_html_path or not os.path.exists(state.report_html_path):
        return jsonify({"error": "no report yet"}), 404
    with open(state.report_html_path, "r", encoding="utf-8") as fh:
        return Response(fh.read(), mimetype="text/html")


@app.route("/api/runs/<run_id>/<path:filename>")
def run_artifact(run_id, filename):
    """Serve sibling artifacts of a run's report (full-domain index links to
    per-host reports with relative hrefs — under this route they resolve to
    /api/runs/<id>/<file>, which lands here). Basenames only, no traversal."""
    state = RUNS.get(run_id)
    if state is None:
        return jsonify({"error": "unknown run"}), 404
    if "/" in filename or "\\" in filename or ".." in filename:
        return jsonify({"error": "bad path"}), 400
    base = os.path.dirname(state.report_html_path or "") or state.audit_path
    target = os.path.join(base, filename)
    if not os.path.isfile(target):
        return jsonify({"error": "not found"}), 404
    with open(target, "r", encoding="utf-8") as fh:
        return Response(fh.read(), mimetype="text/html")


def serve(bind: str = "127.0.0.1", port: int = 8080):
    print(f"[ui] http://{bind}:{port}  (local only — the form holds real credentials)")
    app.run(host=bind, port=port, threaded=True)


def register(subparsers) -> None:
    p = subparsers.add_parser("ui", help="local web UI for the agent")
    p.add_argument("--bind", default="127.0.0.1", help="bind address (default 127.0.0.1)")
    p.add_argument("--port", type=int, default=8080)
    p.set_defaults(func=lambda args: serve(args.bind, args.port))
