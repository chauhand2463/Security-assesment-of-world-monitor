"""Phase 7 tool execution: one runner for every tool kind.

Three kinds run through this module:

  * **Phase 5 adapters** (nmap, httpx + opt-in natools) -- normalized
    ``ToolObservation`` output is persisted through the shared observation
    pipeline; a bounded runner enforces the timeout and cooperative
    cancellation.  ``timeout`` / ``Execution Failed`` attempts are retried once.
  * **legacy scanner shells** (subfinder, assetfinder, dnsx, gau, whatweb,
    nuclei) -- the Phase 3 CLI wrappers are reused verbatim so real nuclei
    ``-json`` output still becomes ``nuclei_finding`` observations.
  * **stdlib probes** (real_dns, real_tcp, real_http) -- always available,
    real facts only.

Every attempt is recorded in ``tool_executions``; every terminal attempt also
writes the legacy ``ToolResult`` row so all existing consumers (SSE, UI,
coverage) keep working.  Nothing here fabricates success for a tool that did
not run.
"""
from __future__ import annotations

import datetime
import time

from app.observations import types as obs_types
from app.orchestration.stages import TOOL_TO_STAGE, enabled as stage_enabled
from app.tools import real_probes
from app.tools import scanner_tools
from app.tools.adapters.registry import get_adapter

_EXTRAS = ("ffuf", "nikto", "sqlmap", "testssl")

_LEGACY_RUNNERS = {
    "subfinder": lambda target: scanner_tools.run_subfinder(target, simulation=False),
    "assetfinder": lambda target: scanner_tools.run_assetfinder(target, simulation=False),
    "gau": lambda target: scanner_tools.run_gau(target, simulation=False),
    "whatweb": lambda target: scanner_tools.run_whatweb(target, simulation=False),
    "nuclei": lambda target: scanner_tools.run_nuclei(target, simulation=False),
    "dnsx": lambda target: scanner_tools.run_dnsx(target, [], simulation=False),
}

_LOG_MAX = 12000


def clip(text: str, limit: int = _LOG_MAX) -> str:
    text = text or ""
    return text[:limit] + ("\n...[truncated]" if len(text) > limit else "")


def _save_result(db, scan_id: int, tool_name: str, result: dict):
    """Write the legacy ToolResult row (Phase 4 consumers) without committing."""
    from database.models import ToolResult

    raw_output = result.get("log", "")
    status_map = {
        "success": "Completed",
        scanner_tools.STATE_NOT_INSTALLED: scanner_tools.STATE_NOT_INSTALLED,
        scanner_tools.STATE_TIMEOUT: scanner_tools.STATE_TIMEOUT,
        scanner_tools.STATE_PARSE_FAILED: scanner_tools.STATE_PARSE_FAILED,
        scanner_tools.STATE_EXECUTION_FAILED: "Failed",
        "skipped": "Skipped",
        "Completed": "Completed",
    }
    status = status_map.get(result.get("status"), "Failed")
    db.add(ToolResult(
        scan_id=scan_id,
        tool_name=tool_name,
        status=status,
        raw_output=clip(raw_output),
    ))


def _begin_execution(db, scan, tool: str, attempt: int) -> object:
    from database.models import ToolExecution

    ex = ToolExecution(
        scan_id=scan.id,
        stage=TOOL_TO_STAGE.get(tool, "VALIDATION"),
        tool=tool,
        adapter=_adapter_kind(tool),
        attempt=attempt,
        status="running",
        target=scan.target,
        started_at=datetime.datetime.utcnow(),
    )
    db.add(ex)
    db.flush()
    return ex


def _adapter_kind(tool: str) -> str:
    if tool == "real_dns":
        return "native_probe"
    if tool == "world_monitor_discovery":
        return "native_probe"
    if get_adapter(tool) is not None:
        return "adapter"
    return "legacy"


def _finish_execution(db, ex, *, status: str, duration_ms: int,
                      parsed_observations: int = 0, command_redacted: list = (),
                      exit_code: int | None = None, stdout_size: int | None = None,
                      stderr_size: int | None = None, stdout_truncated: bool = False,
                      stderr_truncated: bool = False, cancellation_state: str | None = None,
                      termination_reason: str | None = None, error_code: str | None = None):
    from database.models import ToolExecution

    ex.status = status
    ex.finished_at = datetime.datetime.utcnow()
    ex.duration_ms = duration_ms
    ex.parsed_observations = parsed_observations
    ex.command_redacted = " ".join(command_redacted) if command_redacted else None
    ex.exit_code = exit_code
    ex.stdout_size = stdout_size
    ex.stderr_size = stderr_size
    ex.stdout_truncated = bool(stdout_truncated)
    ex.stderr_truncated = bool(stderr_truncated)
    ex.cancellation_state = cancellation_state
    ex.termination_reason = termination_reason
    ex.error_code = error_code
    db.flush()


def _persist_adapter_observations(db, scan, tool: str, target: str,
                                  observations, tool_execution_id: int | None = None) -> int:
    from app.orchestration import events
    from database.models import Observation

    count = 0
    for obs in observations:
        kwargs = obs.to_observation_data(
            scan_id=scan.id,
            tool_name=tool,
            source=obs_types.SOURCE_EXTERNAL_TOOL,
            target=target,
            asset=None,
        )
        row = Observation(tool_execution_id=tool_execution_id, **kwargs)
        db.add(row)
        db.flush()
        events.emit_observation(db, scan.id, row.id, row.kind, row.subject, tool)
        count += 1
    return count


def _persist_legacy_observation(db, scan, ex, *, kind: str, subject: str,
                                data: dict, raw: str):
    from app.orchestration import events
    from database.models import Observation

    row = Observation(
        scan_id=scan.id,
        tool_name=ex.tool,
        kind=kind,
        subject=(subject or scan.target)[:255],
        data_json=data or {},
        raw_output=raw or "",
        tool_execution_id=ex.id,
    )
    db.add(row)
    db.flush()
    events.emit_observation(db, scan.id, row.id, row.kind, row.subject, row.tool_name)


def _extra_options(config: dict, tool: str) -> dict:
    return dict((config or {}).get("tool_options", {}).get(tool) or {})


def execute_tool(db, scan, tool: str, config: dict, job, state: dict) -> dict:
    """Run one planned tool and return its Phase 3-shaped summary dict."""
    from app.orchestration import events

    attempt = 0
    # ``world_monitor_discovery`` is conditional and records its own precise
    # honest state (not_configured vs disabled), so it is routed to its runner
    # instead of the generic disabled gate.
    if tool != "world_monitor_discovery" and not stage_enabled(config, tool):
        _save_result(db, scan.id, tool, {"tool": tool, "status": "skipped",
                                         "log": f"[{tool}] DISABLED by scan configuration."})
        ex = _begin_execution(db, scan, tool, 1)
        _finish_execution(db, ex, status="skipped", duration_ms=0)
        events.emit_tool(db, scan.id, tool, "skipped", attempt=1)
        return {"tool": tool, "status": "skipped"}

    if job is not None:
        from app.workers.tasks import ScanCancelled
        if job.is_cancelled():
            raise ScanCancelled()

    started = time.monotonic()

    if tool == "real_dns":
        return _run_dns_probe(db, scan, tool, config, job, state, started)
    if tool == "real_tcp":
        return _run_tcp_probe(db, scan, tool, config, job, state, started)
    if tool == "real_http":
        return _run_http_probe(db, scan, tool, config, job, state, started)
    if tool == "world_monitor_discovery":
        return _run_world_monitor_discovery(db, scan, tool, config, job, started)
    if tool in _LEGACY_RUNNERS:
        return _run_legacy(db, scan, tool, config, job, started)
    if get_adapter(tool) is not None:
        return _run_adapter(db, scan, tool, config, job, started)
    return {"tool": tool, "status": scanner_tools.STATE_EXECUTION_FAILED}


# ---------------------------------------------------------------------------
# stdlib probes
# ---------------------------------------------------------------------------
def _run_dns_probe(db, scan, tool, config, job, state, started) -> dict:
    from app.orchestration import events

    hosts = state.get("hosts") or [scan.target]
    observations = []
    status = "success"
    for host in hosts:
        report = real_probes.dns_probe(host)
        observations.extend(report.get("observations", []))
    duration_ms = int((time.monotonic() - started) * 1000)
    ex = _begin_execution(db, scan, tool, 1)
    _persist_observations(db, scan, tool, observations, tool_execution_id=ex.id)
    _finish_execution(db, ex, status="completed", duration_ms=duration_ms,
                      parsed_observations=len(observations))
    log = f"[real_dns] {len(observations)} DNS observation(s) recorded for {len(hosts)} host(s)."
    _save_result(db, scan.id, tool, {"status": status, "log": log})
    events.emit_tool(db, scan.id, tool, "completed", attempt=1,
                     detail={"observations": len(observations)})
    return {"tool": tool, "status": status, "observations": observations, "log": log}


def _run_tcp_probe(db, scan, tool, config, job, state, started) -> dict:
    from app.orchestration import events

    hosts = state.get("hosts") or [scan.target]
    observations = []
    for host in hosts:
        report = real_probes.tcp_probe(host)
        observations.extend(report.get("observations", []))
    duration_ms = int((time.monotonic() - started) * 1000)
    ex = _begin_execution(db, scan, tool, 1)
    _persist_observations(db, scan, tool, observations, tool_execution_id=ex.id)
    open_ports = sum(1 for o in observations if o.get("kind") == "tcp_open")
    _finish_execution(db, ex, status="completed", duration_ms=duration_ms,
                      parsed_observations=len(observations))
    log = f"[real_tcp] {open_ports} open port(s); {len(observations)} observation(s)."
    _save_result(db, scan.id, tool, {"status": "success", "log": log})
    events.emit_tool(db, scan.id, tool, "completed", attempt=1,
                     detail={"observations": len(observations), "open_ports": open_ports})
    return {"tool": tool, "status": "success", "observations": observations, "log": log}


def _run_http_probe(db, scan, tool, config, job, state, started) -> dict:
    from app.orchestration import events

    hosts = state.get("hosts") or [scan.target]
    observations = []
    for host in hosts:
        for scheme in ("https", "http"):
            observations.extend(real_probes.http_probe(f"{scheme}://{host}").get("observations", []))
    duration_ms = int((time.monotonic() - started) * 1000)
    ex = _begin_execution(db, scan, tool, 1)
    _persist_observations(db, scan, tool, observations, tool_execution_id=ex.id)
    _finish_execution(db, ex, status="completed", duration_ms=duration_ms,
                      parsed_observations=len(observations))
    log = f"[real_http] {len(observations)} HTTP observation(s) recorded."
    _save_result(db, scan.id, tool, {"status": "success", "log": log})
    events.emit_tool(db, scan.id, tool, "completed", attempt=1,
                     detail={"observations": len(observations)})
    return {"tool": tool, "status": "success", "observations": observations, "log": log}


# ---------------------------------------------------------------------------
# Phase 8 World Monitor discovery (explicit configuration only)
# ---------------------------------------------------------------------------
def _persist_observations(db, scan, tool: str, observations: list,
                          tool_execution_id: int | None = None):
    """Persist legacy probe observation dicts (kind/subject/data/raw shape)."""
    from app.orchestration import events
    from database.models import Observation

    for o in observations:
        row = Observation(
            scan_id=scan.id,
            tool_name=tool,
            kind=(o.get("kind") or "probe_fact"),
            subject=o.get("subject") or scan.target,
            data_json=o.get("data") or {},
            raw_output=clip(o.get("raw") or ""),
            tool_execution_id=tool_execution_id,
        )
        db.add(row)
        db.flush()
        events.emit_observation(db, scan.id, row.id, row.kind, row.subject, tool)


def _wm_guard(db, scan):
    """Scope guard confining WM probes to the deployment hosts + project scope.

    Mirrors ``app.assess.engine._scope_guard`` and the router guard: the
    configured World Monitor hosts and the project's declared scope/assets are
    authorized; everything else is refused before any socket is opened.
    """
    from app.core.auth import is_target_in_scope
    from app.http.fingerprints import host_of
    from database.models import Asset, Project

    project = db.query(Project).filter(Project.id == scan.project_id).first()
    assets = db.query(Asset).filter(Asset.project_id == scan.project_id).all()
    allowed_hosts = {host_of(u).lower() for u in
                     (scan.scan_config or {}).get("world_monitor", {}).values() if isinstance(u, str) and host_of(u)}

    def guard(url: str) -> bool:
        host = host_of(url)
        if not host:
            return False
        if host == scan.target:
            return True
        if host.lower() in allowed_hosts:
            return True
        return bool(project and is_target_in_scope(host, project, assets))

    return guard


def _wm_target_config(db, scan) -> dict | None:
    """Resolve the World Monitor deployment to probe, or None when not configured.

    Priority: an explicitly referenced registered target (config.world_monitor.
    target_id, owned by the scan's project), else an explicitly declared
    configuration (config.world_monitor.base_url).  Cross-host mixes are refused
    exactly like the API router refuses them.
    """
    from app.http.fingerprints import host_of
    from database.models import Project, WorldMonitorTarget

    wm = (scan.scan_config or {}).get("world_monitor") or {}
    if not isinstance(wm, dict):
        return None

    target_id = wm.get("target_id")
    if target_id is not None:
        target = db.query(WorldMonitorTarget).filter(WorldMonitorTarget.id == target_id).first()
        if target is None:
            return None
        owned = db.query(Project).filter(Project.id == target.project_id,
                                         Project.user_id == scan_user_id(db, scan)).first()
        if owned is None:
            return None
        return {"target_id": target.id, "base_url": target.base_url,
                "api_base_url": target.api_base_url, "openapi_url": target.openapi_url,
                "explicit": False}

    base_url = str(wm.get("base_url") or "").strip().rstrip("/")
    if not base_url:
        return None
    allowed = {host_of(base_url).lower()}
    for key in ("api_base_url", "openapi_url"):
        value = str(wm.get(key) or "").strip().rstrip("/") or None
        if value and host_of(value).lower() not in allowed:
            return None
    return {"target_id": wm.get("target_id") or 0, "base_url": base_url,
            "api_base_url": str(wm.get("api_base_url") or "").strip().rstrip("/") or None,
            "openapi_url": str(wm.get("openapi_url") or "").strip().rstrip("/") or None,
            "explicit": True}


def scan_user_id(db, scan):
    from database.models import Project
    project = db.query(Project).filter(Project.id == scan.project_id).first()
    return getattr(project, "user_id", None)


def _run_world_monitor_discovery(db, scan, tool, config, job, started) -> dict:
    """Probe an explicitly configured World Monitor deployment.

    Honest states: when no World Monitor configuration is present, the tool is
    recorded as ``skipped`` (never simulated success).  When configured, the
    deployment is discovered over real sockets and every fact enters the
    observation pipeline through ``build_observation`` with
    provenance ``source=world_monitor``.
    """
    from app.orchestration import events

    from app.integrations.world_monitor import WorldMonitorProvider
    from app.integrations.world_monitor.discovery import TargetConfig
    from app.integrations.world_monitor import normalizers
    from database.models import Observation

    tools_cfg = (config or {}).get("tools") or {}
    if tools_cfg.get(tool) is False:
        duration_ms = int((time.monotonic() - started) * 1000)
        ex = _begin_execution(db, scan, tool, 1)
        _finish_execution(db, ex, status="skipped", duration_ms=duration_ms,
                          termination_reason="disabled by scan configuration")
        _save_result(db, scan.id, tool, {
            "tool": tool, "status": "skipped",
            "log": f"[{tool}] DISABLED by scan configuration."})
        events.emit_tool(db, scan.id, tool, "skipped", attempt=1)
        return {"tool": tool, "status": "skipped"}

    wm = _wm_target_config(db, scan)
    if wm is None:
        duration_ms = int((time.monotonic() - started) * 1000)
        ex = _begin_execution(db, scan, tool, 1)
        _finish_execution(db, ex, status="skipped", duration_ms=duration_ms,
                          termination_reason="no World Monitor configuration supplied")
        db.add(Observation(
            scan_id=scan.id,
            tool_name=tool,
            kind="wm_not_configured",
            subject=scan.target,
            data_json={"status": "not_configured",
                       "reason": "no world_monitor config (target_id or base_url) in scan configuration",
                       "source": "world_monitor"},
            raw_output="[world_monitor_discovery] Skipped: no World Monitor deployment configured for this scan.",
            tool_execution_id=ex.id,
        ))
        db.flush()
        _save_result(db, scan.id, tool, {
            "tool": tool, "status": "skipped",
            "log": "[world_monitor_discovery] Skipped: no World Monitor deployment configured for this scan.",
        })
        events.emit_tool(db, scan.id, tool, "skipped", attempt=1,
                         detail={"reason": "not_configured"})
        return {"tool": tool, "status": "skipped"}

    guard = _wm_guard(db, scan)
    provider = WorldMonitorProvider(guard)
    config_disc = TargetConfig(
        base_url=wm["base_url"],
        api_base_url=wm["api_base_url"],
        openapi_url=wm["openapi_url"],
    )
    result = provider.discover(config_disc)
    target_id = wm["target_id"]
    user_id = str(scan_user_id(db, scan) or "")

    observations = normalizers.health_observations(
        scan_id=scan.id, target_id=target_id, subject=result.health.url if result.health else scan.target,
        tool_name=tool, health=result.health, user_id=user_id,
    )
    for ep in result.endpoints:
        observations.append(normalizers.endpoint_observation(
            scan_id=scan.id, target_id=target_id, endpoint=ep,
            source_url=result.health.url if result.health else scan.target,
            tool_name=tool, user_id=user_id,
        ))

    parsed = 0
    ex = _begin_execution(db, scan, tool, 1)
    for kwargs in observations:
        row = Observation(tool_execution_id=ex.id, **kwargs)
        db.add(row)
        db.flush()
        events.emit_observation(db, scan.id, row.id, row.kind, row.subject, tool)
        parsed += 1

    duration_ms = int((time.monotonic() - started) * 1000)
    _finish_execution(db, ex, status="completed", duration_ms=duration_ms,
                      parsed_observations=parsed,
                      termination_reason=result.error)
    log = (f"[world_monitor_discovery] {result.target_status}; "
           f"{len(result.endpoints)} endpoint(s) from {result.openapi_status or 'no'} OpenAPI; "
           f"{len(observations)} observation(s).")
    _save_result(db, scan.id, tool, {"status": "success", "log": log})
    events.emit_tool(db, scan.id, tool, "completed", attempt=1,
                     detail={"observations": len(observations),
                             "target_status": result.target_status,
                             "endpoint_count": len(result.endpoints)})
    return {"tool": tool, "status": "success", "observations": observations, "log": log}


# ---------------------------------------------------------------------------
# legacy scanner shells
# ---------------------------------------------------------------------------
def _run_legacy(db, scan, tool, config, job, started) -> dict:
    from app.orchestration import events

    target = scan.target
    result = _LEGACY_RUNNERS[tool](target)
    duration_ms = int((time.monotonic() - started) * 1000)
    status = result.get("status") or ""
    terminal = _legacy_terminal(status)

    ex = _begin_execution(db, scan, tool, 1)

    # nuclei real output -> nuclei_finding observations (exactly Phase 3).
    parsed = 0
    if tool == "nuclei" and status == "success":
        for record in result.get("vulnerabilities") or []:
            _persist_legacy_observation(
                db, scan, ex,
                kind="nuclei_finding",
                subject=record.get("matched_at") or record.get("proof_of_concept") or target,
                data={
                    "title": record.get("title"),
                    "severity": record.get("severity"),
                    "cve": record.get("cve"),
                    "cvss": record.get("cvss"),
                    "owasp": record.get("owasp"),
                    "cwe": record.get("cwe"),
                    "description": record.get("description"),
                    "remediation": record.get("remediation"),
                    "matched_at": record.get("matched_at"),
                    "template_id": record.get("template_id"),
                },
                raw=record.get("proof_of_concept") or result.get("log") or "")
            parsed += 1

    err = result.get("error")
    _finish_execution(
        db, ex,
        status=terminal["execution"],
        duration_ms=duration_ms,
        parsed_observations=parsed,
        error_code=terminal["code"],
        termination_reason=err,
        command_redacted=[tool] + result.get("command", []),
    )
    _save_result(db, scan.id, tool, result)
    events.emit_tool(db, scan.id, tool, terminal["event"], attempt=1,
                     detail={"parsed_observations": parsed})
    return dict(result, duration_ms=duration_ms)


def _legacy_terminal(status: str) -> dict:
    if status == "success":
        return {"execution": "completed", "event": "completed", "code": None}
    if status == scanner_tools.STATE_NOT_INSTALLED:
        return {"execution": "not_installed", "event": "not_installed", "code": "not_installed"}
    if status == scanner_tools.STATE_TIMEOUT:
        return {"execution": "timeout", "event": "timeout", "code": "timeout"}
    if status == scanner_tools.STATE_PARSE_FAILED:
        return {"execution": "parse_failed", "event": "parse_failed", "code": "parse_failed"}
    return {"execution": "failed", "event": "failed", "code": "execution_failed"}


# ---------------------------------------------------------------------------
# Phase 5 adapters (bounded + retry on transient failures only)
# ---------------------------------------------------------------------------
_TRANSIENT_STATUSES = (scanner_tools.STATE_TIMEOUT, scanner_tools.STATE_EXECUTION_FAILED)


def _run_adapter(db, scan, tool, config, job, started) -> dict:
    from app.orchestration import events

    adapter = get_adapter(tool)
    if tool in _EXTRAS:
        options = _extra_options(config, tool)
        if not options:
            _save_result(db, scan.id, tool, {
                "tool": tool, "status": "skipped",
                "log": f"[{tool}] opt-in tool has no safe tool_options configured; not scanning blind.",
            })
            ex = _begin_execution(db, scan, tool, 1)
            _finish_execution(db, ex, status="skipped", duration_ms=0)
            events.emit_tool(db, scan.id, tool, "skipped", attempt=1)
            return {"tool": tool, "status": "skipped"}
    else:
        options = _adapter_default_options(tool)

    max_attempts = 2
    last = None
    attempts = 0
    while attempts < max_attempts:
        attempts += 1
        ex = _begin_execution(db, scan, tool, attempts)
        events.emit_tool(db, scan.id, tool, "started", stage=TOOL_TO_STAGE.get(tool),
                         attempt=attempts, detail={"attempt": attempts})
        cancel_check = job.cancel_check if job is not None else None
        result = adapter.run(
            scan.target, simulation=False, options=options, cancel_check=cancel_check)
        duration_ms = result.duration_ms or int((time.monotonic() - started) * 1000)
        parsed = 0
        if result.status == scanner_tools.STATE_COMPLETED:
            parsed = _persist_adapter_observations(
                db, scan, tool, scan.target, result.observations,
                tool_execution_id=ex.id)
        status = _adapter_terminal(result.status)
        _finish_execution(
            db, ex,
            status=status["execution"],
            duration_ms=duration_ms,
            parsed_observations=parsed,
            command_redacted=result.command or [tool],
            exit_code=result.exit_code,
            error_code=status["code"],
            termination_reason=result.error,
        )
        last = (result, parsed, duration_ms, status)
        event_status = status["event"]
        if event_status == "timed_out":
            event_status = "timeout"
        events.emit_tool(db, scan.id, tool, event_status, attempt=attempts,
                         stage=TOOL_TO_STAGE.get(tool),
                         detail={"parsed_observations": parsed,
                                 "duration_ms": duration_ms})
        if status["execution"] not in ("timeout", "failed"):
            break

    result, parsed, duration_ms, status = last
    log = result.raw_output or f"[{tool}] {status['execution']}"
    legacy = {
        "tool": tool,
        "status": _adapter_legacy_status(status["execution"]),
        "log": clip(log),
        "error": result.error,
    }
    _save_result(db, scan.id, tool, legacy)
    return {"tool": tool, "status": legacy["status"],
            "observations": result.observations, "log": legacy["log"],
            "parsed": parsed, "duration_ms": duration_ms}


def _adapter_default_options(tool: str) -> dict:
    if tool == "nmap":
        return {"ports": "80,443,22,3000,3306,5432,8080,8443"}
    return {}


def _adapter_terminal(status: str) -> dict:
    if status == scanner_tools.STATE_COMPLETED:
        return {"execution": "completed", "event": "completed", "code": None}
    if status == scanner_tools.STATE_NOT_INSTALLED:
        return {"execution": "not_installed", "event": "not_installed", "code": "not_installed"}
    if status == scanner_tools.STATE_TIMEOUT:
        return {"execution": "timeout", "event": "timed_out", "code": "timeout"}
    if status == scanner_tools.STATE_PARSE_FAILED:
        return {"execution": "parse_failed", "event": "parse_failed", "code": "parse_failed"}
    return {"execution": "failed", "event": "failed", "code": "execution_failed"}


def _adapter_legacy_status(execution: str) -> str:
    return {
        "completed": "success",
        "not_installed": scanner_tools.STATE_NOT_INSTALLED,
        "timeout": scanner_tools.STATE_TIMEOUT,
        "parse_failed": scanner_tools.STATE_PARSE_FAILED,
    }.get(execution, scanner_tools.STATE_EXECUTION_FAILED)


__all__ = ["execute_tool", "clip"]