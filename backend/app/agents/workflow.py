import time
import json
import datetime
import logging
from database.connection import SessionLocal
from database.models import Scan, ToolResult, Vulnerability, Asset, Report, Observation
from app.tools.scanner_tools import (
    run_subfinder, run_assetfinder, run_dnsx, run_nmap,
    run_httpx, run_nuclei, run_gau, run_whatweb,
    STATE_NOT_INSTALLED, STATE_TIMEOUT, STATE_PARSE_FAILED, STATE_EXECUTION_FAILED,
)
from app.tools import real_probes
from app.assess import finding_rules
from app.agents import lifecycle
from app.workers.tasks import registry, ScanCancelled

logger = logging.getLogger("cyberagent.workflow")

# ---------------------------------------------------------------------------
# Stage definitions: ordered lifecycle + the tasks each stage owns.
# Every planned task is counted for coverage; a task only counts as
# completed when its ToolResult row reaches the "Completed" status.
# NOT_INSTALLED tools never increase coverage, so a truncated tool set
# honestly lowers the assessment coverage metric.
# ---------------------------------------------------------------------------
ALL_TOOLS = ["subfinder", "assetfinder", "dnsx", "nmap", "httpx", "gau", "whatweb", "nuclei"]

STAGE_TOOLS = {
    lifecycle.RECON: ["subfinder", "assetfinder"],
    lifecycle.DISCOVERY: ["dnsx"],
    lifecycle.SERVICE_SCAN: ["nmap"],
    lifecycle.HTTP_SCAN: ["httpx", "gau", "whatweb"],
    lifecycle.VULNERABILITY_SCAN: ["nuclei"],
}

# Stdlib probe groups only run in real mode; each group is one planned task.
PROBE_TOOLS = ["real_dns", "real_tcp", "real_http"]

SEVERITY_THRESHOLD = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "all": -1}


def _merge_config(requested: dict | None, stored: dict | None) -> dict:
    """Sanitize a scan-config payload into the persisted scan_config shape."""
    base = dict(stored or {})
    req = dict(requested or {})
    tools_req = req.get("tools")
    if isinstance(tools_req, dict):
        normalized = {}
        for name in ALL_TOOLS:
            if name in tools_req:
                normalized[name] = bool(tools_req.get(name))
            else:
                normalized[name] = bool((base.get("tools") or {}).get(name, True))
        base["tools"] = normalized
    else:
        base["tools"] = dict(base.get("tools") or {t: True for t in ALL_TOOLS})
    severity = str(req.get("severity") or base.get("severity") or "all").lower()
    base["severity"] = severity if severity in SEVERITY_THRESHOLD else "all"
    base["profile"] = str(req.get("profile") or base.get("profile") or "steady")
    # Phase 5: active testing is opt-in and off by default; the assessment engine
    # itself is on by default.  Optional assessment inputs are passed through.
    base["active_testing"] = bool(req.get("active_testing", base.get("active_testing", False)))
    if "assessment_engine" in req:
        base["assessment_engine"] = bool(req.get("assessment_engine"))
    for key in ("auth_identities", "ssrf_validation_url", "ssrf_token", "jwt_tokens",
                "jwt_alg_none_accepted", "installed_tools", "tools_missing",
                "world_monitor", "max_parallel_tools"):
        if key in req:
            base[key] = req[key]
    return base


def _enabled_tools(config: dict) -> dict:
    return {t: bool((config or {}).get("tools", {}).get(t, True)) for t in ALL_TOOLS}


# ---------------------------------------------------------------------------
# Stage / progress persistence helpers
# ---------------------------------------------------------------------------
def _set_stage(db, scan: Scan, stage: str, log_line: str):
    """Transition the job stage, derive coarse status, and append a log line.

    Emits a real ``stage`` scan event (Phase 10.8) so the legacy orchestrator is
    ledger-backed like the Phase 7 pipeline: the live SSE stream is a typed
    cursor over ``scan_events`` and a reconnecting client can resume stage
    transitions instead of re-deriving them from a snapshot.
    """
    scan.stage = stage
    if not lifecycle.is_terminal(stage):
        scan.status = lifecycle.coarse_status(stage)
    scan.updated_at = datetime.datetime.utcnow()
    scan.logs = (scan.logs or "") + log_line + "\n"
    from app.orchestration import events as phase7_events
    phase7_events.emit_stage(db, scan.id, stage, "started")
    db.commit()


def _persist_progress(db, scan: Scan, progress: dict):
    """Persist structured progress + the derived coverage metric.

    Emits a real ``progress`` scan event (Phase 10.8) whenever the percentage
    actually changes, so the live SSE stream stays ledger-backed: a reconnecting
    client can resume progress updates from the persisted event stream instead
    of re-deriving them from the current snapshot.
    """
    progress["percent"] = 0
    total = progress.get("total_tasks") or 0
    completed = progress.get("completed_tasks") or 0
    if total > 0:
        progress["percent"] = round(100.0 * min(completed, total) / total, 1)
    prev_percent = (scan.progress or {}).get("percent")
    scan.progress = progress
    scan.coverage = lifecycle.compute_coverage(progress)
    scan.updated_at = datetime.datetime.utcnow()
    db.commit()
    if progress["percent"] != prev_percent and scan.id and total > 0:
        from app.orchestration import events as phase7_events
        phase7_events.emit(db, scan.id, phase7_events.EVENT_PROGRESS, {
            "percent": progress["percent"],
            "coverage": scan.coverage,
            "completed": progress.get("completed_tasks") or 0,
            "total": progress.get("total_tasks") or 0,
        })
        db.commit()


def _check_cancel(scan_id: int):
    job = registry.get(scan_id)
    if job is not None and job.is_cancelled():
        raise ScanCancelled()


def _planned_tasks(config: dict, simulation: bool) -> list[str]:
    """The ordered list of planned tool/probe task names for this run."""
    enabled = _enabled_tools(config)
    planned = []
    for stage in lifecycle.STAGES:
        for tool in STAGE_TOOLS.get(stage, []):
            if enabled.get(tool):
                planned.append(tool)
    if not simulation:
        planned += PROBE_TOOLS
    return planned


def _seed_progress(db, scan: Scan, config: dict, simulation: bool):
    planned = _planned_tasks(config, simulation)
    progress = lifecycle.empty_progress()
    progress["total_tasks"] = len(planned)
    progress["total_tools"] = len([t for t in planned if t not in PROBE_TOOLS])
    progress["planned_tasks"] = planned
    _persist_progress(db, scan, progress)
    return progress


# ---------------------------------------------------------------------------
# Orchestrator (lifecycle: staged, cancellable, coverage-aware)
# ---------------------------------------------------------------------------
def orchestrate_scan(scan_id: int, simulation: bool = True, config: dict | None = None):
    """Run a scan through the lifecycle as a background job.

    Stages advance in order (recon -> discovery -> service_scan -> http_scan ->
    vulnerability_scan -> analysis -> reporting -> completed).  Progress and
    coverage are persisted; cancellation is honored between stages/tools and
    inside the stdlib probe loops.  Findings are ALWAYS derived exclusively
    from persisted observations -- never fabricated.
    """
    db = SessionLocal()
    scan = None
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            logger.error(f"Scan ID {scan_id} not found in database.")
            return

        job = registry.get(scan_id)
        if job is not None:
            job.attach_thread(__import__("threading").current_thread())

        config = _merge_config(config, scan.scan_config)
        scan.scan_config = config
        scan.started_at = datetime.datetime.utcnow()
        _set_stage(db, scan, lifecycle.STARTING, "[Worker] Scan job started; scheduling stages.")

        if simulation:
            scan.logs += (
                "[SIMULATION] Scan running in SIMULATION_MODE: no real probes run and "
                "no findings are produced. All output is synthetic and must NOT be "
                "treated as a real security assessment.\n"
            )
            db.commit()

        target = scan.target
        progress = _seed_progress(db, scan, config, simulation)
        enabled = _enabled_tools(config)
        severity_filter = config.get("severity") or "all"

        # ----------------------------------------------------
        # RECON stage -- passive subdomain discovery
        # ----------------------------------------------------
        _set_stage(db, scan, lifecycle.RECON, "[Recon] Gathering subdomains (subfinder, assetfinder)...")
        subdomains: list[str] = []
        subfinder_res = _run_tool(db, scan, "subfinder", enabled, simulation,
                                   lambda: run_subfinder(target, simulation), progress)
        asset_res = _run_tool(db, scan, "assetfinder", enabled, simulation,
                              lambda: run_assetfinder(target, simulation), progress)
        subdomains = list(set(subfinder_res.get("subdomains", []) + asset_res.get("subdomains", [])))

        # ----------------------------------------------------
        # DISCOVERY stage -- DNS resolution (scope-gated)
        # ----------------------------------------------------
        _set_stage(db, scan, lifecycle.DISCOVERY, "[Discovery] Resolving discovered subdomains (dnsx)...")
        candidates = list(dict.fromkeys([target] + [s for s in subdomains if s != target]))
        hosts = _in_scope_hosts(db, scan, candidates)
        dnsx_res = _run_tool(db, scan, "dnsx", enabled, simulation,
                             lambda: run_dnsx(target, hosts if hosts else [target], simulation), progress)

        for sub in hosts:
            add_asset(db, scan.project_id, "domain", sub, {"status": "discovered", "source": "recon"}, scan_id=scan.id)
        for item in dnsx_res.get("resolved", []):
            add_asset(db, scan.project_id, "ip", item["ip"], {"domain": item["subdomain"], "source": "dnsx"}, scan_id=scan.id)
        db.commit()

        # ----------------------------------------------------
        # SERVICE_SCAN stage -- port/service discovery
        # ----------------------------------------------------
        _set_stage(db, scan, lifecycle.SERVICE_SCAN, "[Service Scan] Probing services (nmap)...")
        nmap_res = _run_tool(db, scan, "nmap", enabled, simulation,
                             lambda: run_nmap(target, simulation), progress)
        for p in nmap_res.get("ports", []):
            if p.get("state") == "open":
                add_asset(db, scan.project_id, "port", f"{p['port']}/{p['protocol']}", {
                    "service": p.get("service"), "product": p.get("product"),
                    "version": p.get("version"), "source": "nmap",
                }, scan_id=scan.id)
        db.commit()

        # ----------------------------------------------------
        # HTTP_SCAN stage -- web probing, URL discovery, tech fingerprinting
        # ----------------------------------------------------
        _set_stage(db, scan, lifecycle.HTTP_SCAN, "[HTTP Scan] Probing web layer (httpx, gau, whatweb)...")
        httpx_res = _run_tool(db, scan, "httpx", enabled, simulation,
                              lambda: run_httpx(target, simulation), progress)
        gau_res = _run_tool(db, scan, "gau", enabled, simulation,
                            lambda: run_gau(target, simulation), progress)
        whatweb_res = _run_tool(db, scan, "whatweb", enabled, simulation,
                                lambda: run_whatweb(target, simulation), progress)
        for tech in whatweb_res.get("techs", []):
            add_asset(db, scan.project_id, "tech", tech, {"source": "whatweb"}, scan_id=scan.id)
        db.commit()

        # ----------------------------------------------------
        # VULNERABILITY_SCAN stage -- nuclei (real engine output only)
        # ----------------------------------------------------
        _set_stage(db, scan, lifecycle.VULNERABILITY_SCAN, "[Vulnerability Scan] Running nuclei...")
        nuclei_res = _run_tool(db, scan, "nuclei", enabled, simulation,
                               lambda: run_nuclei(target, simulation), progress)

        # ----------------------------------------------------
        # REAL EVIDENCE PIPELINE (real mode only): stdlib probes +
        # nuclei output -> persisted observations.
        # ----------------------------------------------------
        if not simulation:
            _set_stage(db, scan, lifecycle.VULNERABILITY_SCAN,
                       "[Evidence] Running real DNS/TCP/HTTP probes and persisting observations...")
            _run_real_evidence_pipeline(db, scan, target, hosts, nuclei_res, enabled, progress)

        # ----------------------------------------------------
        # ANALYSIS stage -- findings from persisted observations only
        # ----------------------------------------------------
        _set_stage(db, scan, lifecycle.ANALYSIS, "[Analysis] Deriving findings exclusively from persisted observations...")
        time.sleep(0.5 if simulation else 1)

        if simulation:
            scan.security_score = 100
            scan.logs += (
                "[Analysis] Simulation mode: 0 observations, 0 findings. "
                "No security findings were fabricated.\n"
            )
            db.commit()
        else:
            observations = _scan_observations(db, scan.id)
            candidates = finding_rules.evaluate_observations(observations, config=config)
            if severity_filter and severity_filter in SEVERITY_THRESHOLD and severity_filter != "all":
                threshold = SEVERITY_THRESHOLD[severity_filter]
                candidates = [
                    c for c in candidates
                    if SEVERITY_THRESHOLD.get((c.get("severity") or "info").lower(), 99) >= threshold
                ]
            existing = db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).all()
            existing_keys = {
                v.dedup_key for v in existing
                if v.dedup_key and (v.state or "NEW").upper() not in finding_rules.RESOLVED_STATES
            }
            candidates = finding_rules.deduplicate(candidates, existing_keys)
            for candidate in candidates:
                _check_cancel(scan.id)
                db.add(_persisted_finding(scan, candidate, target))
            db.commit()
            scan.logs += (
                f"[Analysis] Rule engine applied to {len(observations)} observations "
                f"produced {len(candidates)} evidence-backed finding(s).\n"
            )
            findings = db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).all()
            finding_dicts = [{"severity": f.severity or "Info", "state": f.state or "NEW"} for f in findings]
            scan.security_score = finding_rules.compute_score(finding_dicts)
            scan.logs += (
                f"[Analysis] Evaluation complete. Security score calculated "
                f"from {len(findings)} persisted finding(s): {scan.security_score}/100\n"
            )
            db.commit()

            # Phase 5 assessment engine: deterministic tests over the same
            # persisted observations.  Active (mutating) testing is opt-in via
            # config["active_testing"]; requests are scope-guarded and no finding
            # is ever fabricated.  Inapplicable tests are reported as coverage.
            try:
                from app.assess import engine as assessment_engine

                summary = assessment_engine.run_assessment(db, scan, simulation=False, config=config)
                if summary.get("executed"):
                    cov = summary.get("coverage") or {}
                    scan.logs += (
                        f"[Assessment] Phase 5 engine ran {cov.get('tests_executed', 0)}/"
                        f"{cov.get('tests_applicable', 0)} applicable test(s) "
                        f"(active_testing={summary.get('active_testing')}); "
                        f"coverage {cov.get('coverage_percent')}%; "
                        f"{summary.get('findings_confirmed', 0)} confirmed finding(s). "
                        "Unevaluated areas are reported as coverage, never as zero risk.\n"
                    )
                    findings = db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).all()
                    finding_dicts = [{"severity": f.severity or "Info", "state": f.state or "NEW"} for f in findings]
                    scan.security_score = finding_rules.compute_score(finding_dicts)
                else:
                    scan.logs += f"[Assessment] Phase 5 engine not executed: {summary.get('reason')}.\n"
                db.commit()
            except Exception as exc:  # a failure here must never fail the scan
                logger.warning(f"Phase 5 assessment engine failed for scan {scan.id}: {exc}")
                scan.logs += f"[Assessment] Phase 5 engine skipped after error: {exc}\n"
                db.commit()

        # ----------------------------------------------------
        # REPORTING stage -- strictly downstream of persisted data
        # ----------------------------------------------------
        _set_stage(db, scan, lifecycle.REPORTING, "[Reporting] Generating report from persisted findings and observations...")

        findings = db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).order_by(Vulnerability.id.asc()).all()
        observations = _scan_observations(db, scan.id)
        findings_payload = [_finding_dict(f) for f in findings]
        observations_payload = [
            {"id": o["id"], "tool": o["tool"], "kind": o["kind"], "subject": o["subject"],
             "data": o["data"], "raw": o["raw"]}
            for o in observations
        ]

        markdown_report = generate_markdown_report_content(scan, findings, observations, simulation)
        html_report = generate_html_report_content(scan, markdown_report)

        report_obj = Report(
            scan_id=scan.id,
            title=f"Security Assessment Report for {target}",
            markdown_content=markdown_report,
            json_content={
                "target": target,
                "security_score": scan.security_score,
                "security_coverage": scan.coverage,
                "simulation": simulation,
                "findings": findings_payload,
                "observations": observations_payload,
                "subdomains": hosts,
                "coverage": scan.coverage,
            },
            html_content=html_report,
            pdf_content=markdown_report.encode("utf-8")
        )
        db.add(report_obj)
        db.commit()

        # ----------------------------------------------------
        # Terminal transition
        # ----------------------------------------------------
        _check_cancel(scan.id)
        failed_tasks = progress.get("failed_tasks") or 0
        if failed_tasks > 0:
            _set_stage(db, scan, lifecycle.PARTIAL,
                       "[Reporting] Scan completed with partial success "
                       f"({failed_tasks} planned task(s) failed).")
        else:
            _set_stage(db, scan, lifecycle.COMPLETED, "[Reporting] Scan completed.")
        scan.status = lifecycle.coarse_status(scan.stage)
        if scan.status in ("Completed", "Partially Completed"):
            scan.completed_at = datetime.datetime.utcnow()
        scan.updated_at = datetime.datetime.utcnow()
        if simulation:
            scan.logs += "[SIMULATION] This scan ran in simulation mode; findings would be synthetic (none produced).\n"
        db.commit()

    except ScanCancelled:
        logger.info(f"Scan {scan_id} cancelled.")
        if scan is not None:
            scan.stage = lifecycle.CANCELLED
            scan.status = "Cancelled"
            scan.cancelled_at = datetime.datetime.utcnow()
            scan.updated_at = datetime.datetime.utcnow()
            scan.logs += "[Worker] Scan cancelled by user; remaining stages abandoned.\n"
            db.commit()
    except Exception as e:
        logger.error(f"Error in orchestrating scan: {e}")
        if scan is not None:
            scan.stage = lifecycle.FAILED
            scan.status = "Failed"
            scan.error = str(e)[:500]
            scan.completed_at = datetime.datetime.utcnow()
            scan.updated_at = datetime.datetime.utcnow()
            scan.logs += f"[System Error] Scan failed due to: {e}\n"
            db.commit()
    finally:
        db.close()


def _run_tool(db, scan: Scan, tool_name: str, enabled: dict, simulation: bool,
              runner, progress: dict) -> dict:
    """Run one tool as a planned task, persist its result, and update progress.

    Returns an honest empty result shape when the tool is disabled by config.
    """
    from app.orchestration import events as phase7_events

    if not enabled.get(tool_name):
        fake = {"tool": tool_name, "status": "skipped", "log": f"[{tool_name}] DISABLED by scan configuration."}
        phase7_events.emit_tool(db, scan.id, tool_name, "skipped", attempt=1)
        db.commit()
        return fake

    _check_cancel(scan.id)
    scan.logs += f"[{tool_name}] executing...\n"
    phase7_events.emit_tool(db, scan.id, tool_name, "started", attempt=1)
    db.commit()
    result = runner()
    status = result.get("status") or ""
    save_tool_result(db, scan.id, tool_name, result, simulated=simulation)
    if status in (STATE_EXECUTION_FAILED, STATE_TIMEOUT, STATE_PARSE_FAILED):
        event_status = "failed"
        progress["failed_tasks"] = (progress.get("failed_tasks") or 0) + 1
    elif status == "skipped":
        event_status = "skipped"
    else:
        if status == "success":
            progress["completed_tasks"] = (progress.get("completed_tasks") or 0) + 1
            progress["completed_tools"] = (progress.get("completed_tools") or 0) + 1
        event_status = "completed"
    phase7_events.emit_tool(db, scan.id, tool_name, event_status, attempt=1)
    progress["last_tool"] = tool_name
    _persist_progress(db, scan, progress)
    _check_cancel(scan.id)
    return result


def _run_probe(db, scan: Scan, tool_name: str, report_runner, progress: dict):
    """Run a stdlib probe group as one planned task (real mode only)."""
    _check_cancel(scan.id)
    result = report_runner()
    _persist_probe(db, scan, tool_name, result)
    progress["completed_tasks"] = (progress.get("completed_tasks") or 0) + 1
    progress["last_tool"] = tool_name
    _persist_progress(db, scan, progress)
    _check_cancel(scan.id)
    return result


# ---------------------------------------------------------------------------
# Scope guards for discovered hosts (never probe what is not authorized)
# ---------------------------------------------------------------------------
def _in_scope_hosts(db, scan: Scan, candidates: list[str]) -> list[str]:
    from app.core.auth import is_target_in_scope
    from database.models import Project, Asset

    project = db.query(Project).filter(Project.id == scan.project_id).first()
    assets = db.query(Asset).filter(Asset.project_id == scan.project_id).all()
    out = []
    for host in candidates:
        if host == scan.target:
            out.append(host)
            continue
        if project is not None and is_target_in_scope(host, project, assets):
            out.append(host)
        else:
            db.add(Observation(
                scan_id=scan.id,
                tool_name="scope_guard",
                kind="out_of_scope_skipped",
                subject=host,
                data_json={"reason": "discovered host outside authorized scope",
                           "scope": project.scope_json if project else []},
                raw_output=f"[scope_guard] Skipped {host}: discovered host outside authorized scope.",
            ))
            scan.logs += f"[scope_guard] Skipped out-of-scope host {host}; not scanned.\n"
    db.commit()
    return out


# ---------------------------------------------------------------------------
# Real evidence pipeline
# ---------------------------------------------------------------------------
def _run_real_evidence_pipeline(db, scan: Scan, target: str, subdomains: list, nuclei_res: dict,
                                enabled: dict | None = None, progress: dict | None = None):
    """Real probes -> observations + assets. External nuclei output, when real,
    is normalized into ``nuclei_finding`` observations before the rule engine sees it."""
    enabled = enabled if enabled else {t: True for t in ALL_TOOLS}
    progress = progress if progress is not None else lifecycle.empty_progress()
    hosts = list(dict.fromkeys([target] + [s for s in subdomains if s != target]))

    if enabled.get("dnsx") is not False:
        for host in hosts:
            _run_probe(db, scan, "real_dns", lambda h=host: real_probes.dns_probe(h), progress)

    for host in hosts:
        _run_probe(db, scan, "real_tcp", lambda h=host: real_probes.tcp_probe(h), progress)

    for host in hosts:
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}"
            _run_probe(db, scan, "real_http", lambda u=url: real_probes.http_probe(u), progress)

    for record in (nuclei_res.get("vulnerabilities") or []):
        db.add(Observation(
            scan_id=scan.id,
            tool_name="nuclei",
            kind="nuclei_finding",
            subject=record.get("matched_at") or record.get("proof_of_concept") or scan.target,
            data_json={
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
            raw_output=(record.get("proof_of_concept") or json.dumps(record, default=str)),
        ))
    _persist_progress(db, scan, progress)
    db.commit()


def _persist_probe(db, scan: Scan, tool_name: str, report: dict):
    """Persist probe observations verbatim plus a ToolResult row for the tool."""
    for obs in (report.get("observations") or []):
        db.add(Observation(
            scan_id=scan.id,
            tool_name=tool_name,
            kind=obs["kind"],
            subject=obs["subject"],
            data_json=obs.get("data") or {},
            raw_output=obs.get("raw") or "",
        ))
    save_tool_result(db, scan.id, tool_name,
                     {"status": report.get("status", "success"), "log": report.get("log", "")},
                     simulated=False)


# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------
def _scan_observations(db, scan_id: int) -> list:
    rows = db.query(Observation).filter(Observation.scan_id == scan_id).order_by(Observation.id.asc()).all()
    return [
        {"id": o.id, "tool": o.tool_name, "kind": o.kind, "subject": o.subject,
         "data": o.data_json or {}, "raw": o.raw_output or ""}
        for o in rows
    ]


def _evidence_text(candidate: dict) -> str:
    obs_ids = candidate.get("observation_ids") or []
    ids = ", ".join(f"#{i}" for i in obs_ids)
    proof = (candidate.get("proof") or "").strip()
    base = (
        f"Derived by rule {candidate['rule_id']} from persisted observation(s) {ids}; "
        "traceable via tool -> scan -> authorized target."
    )
    if proof:
        return base + " Evidence: " + proof
    return base


def _persisted_finding(scan: Scan, candidate: dict, fallback_target: str) -> Vulnerability:
    now = datetime.datetime.utcnow()
    return Vulnerability(
        scan_id=scan.id,
        title=candidate["title"],
        severity=candidate["severity"],
        description=candidate["description"],
        remediation=candidate.get("remediation"),
        cve=candidate.get("cve"),
        cvss=candidate.get("cvss"),
        owasp=candidate.get("owasp"),
        cwe=candidate.get("cwe"),
        target=candidate.get("target") or fallback_target,
        proof_of_concept=candidate.get("proof"),
        rule_id=candidate.get("rule_id"),
        dedup_key=candidate.get("dedup_key"),
        confidence=candidate.get("confidence"),
        state="NEW",
        evidence=_evidence_text(candidate),
        evidence_observation_ids=candidate.get("observation_ids") or [],
        created_at=now,
    )


def _finding_dict(f: Vulnerability) -> dict:
    return {
        "id": f.id,
        "title": f.title,
        "severity": f.severity,
        "state": f.state or "NEW",
        "rule_id": f.rule_id,
        "confidence": f.confidence,
        "cve": f.cve,
        "cvss": f.cvss,
        "owasp": f.owasp,
        "cwe": f.cwe,
        "target": f.target,
        "evidence": f.evidence,
        "evidence_observation_ids": f.evidence_observation_ids or [],
        "remediation": f.remediation,
    }


def save_tool_result(db, scan_id: int, tool_name: str, result: dict, simulated: bool = False):
    raw_output = result.get("log", "")
    if simulated:
        raw_output = (
            "[SIMULATED] Tool output is synthetic (SIMULATION_MODE). "
            "This is NOT the result of a real security assessment.\n" + raw_output
        )

    status_map = {
        "success": "Completed",
        STATE_NOT_INSTALLED: STATE_NOT_INSTALLED,
        STATE_TIMEOUT: STATE_TIMEOUT,
        STATE_PARSE_FAILED: STATE_PARSE_FAILED,
        STATE_EXECUTION_FAILED: "Failed",
        "skipped": "Skipped",
    }
    status = status_map.get(result.get("status"), "Failed")
    tool_result = ToolResult(
        scan_id=scan_id,
        tool_name=tool_name,
        status=status,
        raw_output=raw_output
    )
    db.add(tool_result)
    db.commit()


def add_asset(db, project_id: int, asset_type: str, value: str, metadata: dict,
              scan_id: int | None = None):
    """Persist a discovered asset (deduplicated) and emit ``asset.discovered``.

    ``metadata`` may carry ``source``; the Phase 9 columns (scan_id, source)
    are populated additively when the caller provides the owning scan.
    """
    from app.orchestration import events

    existing = db.query(Asset).filter(Asset.project_id == project_id, Asset.type == asset_type, Asset.value == value).first()
    if existing:
        return existing
    asset = Asset(project_id=project_id, type=asset_type, value=value,
                  metadata_json=metadata, scan_id=scan_id,
                  source=(metadata or {}).get("source") or None)
    db.add(asset)
    db.flush()
    if scan_id is not None:
        events.emit_asset_discovered(
            db, scan_id, asset.id, asset_type, value,
            (metadata or {}).get("source") or "",
        )
    return asset


def generate_markdown_report_content(scan, findings, observations, simulation=False) -> str:
    timestamp = scan.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")
    mode = "SIMULATION - no findings produced" if simulation else "REAL - evidence-backed findings"
    buf = list()
    buf.append("# Security Assessment Report")
    buf.append("")
    buf.append(f"**Target**: `{scan.target}`")
    buf.append(f"**Date**: {timestamp}")
    buf.append(f"**Security Score**: `{scan.security_score}/100`")
    buf.append(f"**Assessment Coverage**: `{scan.coverage if scan.coverage is not None else 'n/a'}%`")
    buf.append(f"**Status**: `COMPLETED`")
    buf.append(f"**Mode**: `{mode}`")
    buf.append("")
    buf.append("---")
    buf.append("")
    buf.append("## Executive Summary")
    buf.append("")
    buf.append(
        "This report summarizes the security assessment conducted on target network "
        f"`{scan.target}`. Findings are derived exclusively from persisted observations; "
        "a finding with no evidence is never reported."
    )
    buf.append("")
    buf.append(f"We identified **{len(findings)} finding(s)**. Review the list below for direct mitigation techniques.")
    buf.append("")
    buf.append("---")
    buf.append("")
    buf.append("## Findings")
    buf.append("")

    if not findings:
        buf.append("No evidence-backed findings were produced for this scan.")
        buf.append("")
    else:
        for idx, f in enumerate(findings, 1):
            buf.append(f"### {idx}. {f.title}")
            buf.append("")
            buf.append(f"* **Severity**: `{f.severity}`")
            buf.append(f"* **State**: `{f.state or 'NEW'}`")
            buf.append(f"* **Rule**: `{f.rule_id or 'legacy'}`")
            buf.append(f"* **Confidence**: `{f.confidence or 'n/a'}`")
            buf.append(f"* **CVSS Score**: `{f.cvss or 'N/A'}`")
            buf.append(f"* **CVE Reference**: `{f.cve or 'N/A'}`")
            buf.append(f"* **OWASP Mapping**: `{f.owasp or 'N/A'}`")
            buf.append(f"* **CWE**: `{f.cwe or 'N/A'}`")
            buf.append("")
            buf.append("#### Description")
            buf.append(f.description)
            buf.append("")
            buf.append("#### Remediation")
            buf.append(f.remediation or "No remediation provided.")
            buf.append("")
            if f.proof_of_concept:
                buf.append("#### Evidence (verbatim)")
                buf.append("```text")
                buf.append(f.proof_of_concept)
                buf.append("```")
                buf.append("")
            if f.evidence:
                buf.append("#### Evidence trail")
                buf.append(f.evidence)
                buf.append("")
            buf.append("---")
            buf.append("")

    if observations:
        buf.append("## Evidence & Methodology (persisted observations)")
        buf.append("")
        for o in observations:
            buf.append(f"* `{o['kind']}` by {o['tool']} on {o['subject']}")
        buf.append("")
    return "\n".join(buf)


def generate_html_report_content(scan, markdown_content) -> str:
    # A simple, premium styled HTML fallback for rendering
    html_body = markdown_content.replace('\n', '<br>')
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CyberAgent Security Report - {scan.target}</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0b0f19; color: #f8fafc; padding: 40px; line-height: 1.6; }}
            h1, h2, h3 {{ color: #22c55e; }}
            pre {{ background: #020617; border: 1px solid #1e293b; padding: 15px; border-radius: 8px; overflow-x: auto; color: #a7f3d0; }}
            code {{ font-family: Consolas, monospace; background: #1e293b; padding: 2px 6px; border-radius: 4px; }}
            .card {{ background: #1e293b; border-radius: 8px; padding: 20px; margin-bottom: 20px; border-left: 5px solid #ef4444; }}
        </style>
    </head>
    <body>
        <h1>CyberAgent Security Assessment Report</h1>
        <p><strong>Target:</strong> {scan.target}</p>
        <p><strong>Score:</strong> {scan.security_score}/100</p>
        <hr>
        <div>
            {html_body}
        </div>
    </body>
    </html>
    """