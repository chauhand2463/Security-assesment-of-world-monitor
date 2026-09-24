import datetime
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, ForeignKey, Float, JSON, Boolean, LargeBinary
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, backref

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(String(255), primary_key=True)  # Generated locally at registration
    email = Column(String(255), nullable=False, unique=True)
    password_hash = Column(String(512), nullable=True)  # PBKDF2-HMAC-SHA256; NULL for legacy/historical rows
    role = Column(String(50), nullable=False, default="user")  # "admin" | "user"
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    projects = relationship("Project", back_populates="user", cascade="all, delete-orphan")
    sessions = relationship("Session", back_populates="user", cascade="all, delete-orphan")


class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    user_id = Column(String(255), ForeignKey("users.id"), nullable=False)
    scope_json = Column(JSON, default=list)  # List of authorized targets (domains, IPs, CIDRs) owned by the user
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    user = relationship("User", back_populates="projects")
    assets = relationship("Asset", back_populates="project", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="project", cascade="all, delete-orphan")


class Session(Base):
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    token_hash = Column(String(64), nullable=False, unique=True, index=True)  # SHA-256 of the opaque token
    user_id = Column(String(255), ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    revoked_at = Column(DateTime, nullable=True)

    user = relationship("User", back_populates="sessions")


class Asset(Base):
    """An asset discovered for a project.

    ``type`` distinguishes the classes the platform records: domain, ip, port,
    tech, host, service, endpoint.  ``parent_asset_id`` (Phase 9) links
    discovered facts into the asset graph (host -> service -> endpoint, or an
    endpoint owned by a host), so every edge is a *real* parent/child link to
    a persisted row that also exists.  ``source`` records how the asset was
    discovered (scan probe, external tool, world monitor, operator) and
    ``scan_id`` the scan that first surfaced it, both nullable and additive.
    """
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    type = Column(String(50), nullable=False)  # "domain", "ip", "port", "tech", "host", "service", "endpoint"
    value = Column(String(255), nullable=False)  # e.g., "api.target.com", "192.168.1.1", "80/tcp"
    metadata_json = Column(JSON, default=dict)  # e.g., technology details, port status
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Phase 9 asset graph (additive, nullable).
    parent_asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True)
    source = Column(String(100), nullable=True)  # how the asset was discovered
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)  # scan that first surfaced it

    project = relationship("Project", back_populates="assets")
    children = relationship("Asset", backref=backref("parent", remote_side=[id]))


class Scan(Base):
    """A single security assessment job (Phase 4: job lifecycle model).

    ``status`` is the coarse, terminal-compatible state used across the API
    (Pending/Running/Completed/Failed/Cancelled). ``stage`` tracks the detailed
    job lifecycle (queued/starting/recon/discovery/service_scan/http_scan/
    vulnerability_scan/analysis/reporting) and is the source of progress events.
    ``progress`` and ``coverage`` are structured, persisted progress metadata and
    are never fabricated: counters increment only from real stage/tool completions.
    """
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    target = Column(String(255), nullable=False)  # IP, domain, or CIDR
    status = Column(String(50), default="Pending")  # "Pending", "Running", "Completed", "Failed", "Cancelled"
    stage = Column(String(50), default="queued")  # job lifecycle stage (see app.agents.lifecycle)
    progress = Column(JSON, default=dict)  # {completed_tasks, total_tasks, completed_tools, total_tools, ...}
    coverage = Column(Float, nullable=True)  # assessment coverage % (0-100), distinct from risk score
    scan_config = Column(JSON, default=dict)  # enabled tools / severity profile captured at trigger
    cancel_requested = Column(Boolean, default=False)
    started_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, nullable=True)
    cancelled_at = Column(DateTime, nullable=True)
    error = Column(Text, nullable=True)
    security_score = Column(Integer, default=100)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    logs = Column(Text, default="")  # Live streamed execution logs

    project = relationship("Project", back_populates="scans")
    tool_results = relationship("ToolResult", back_populates="scan", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")
    observations = relationship("Observation", back_populates="scan", cascade="all, delete-orphan")
    assessment_tests = relationship("AssessmentTest", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="scan", cascade="all, delete-orphan")
    chats = relationship("ChatHistory", back_populates="scan", cascade="all, delete-orphan")
    report_exports = relationship("ReportExport", back_populates="scan", cascade="all, delete-orphan")

    # Phase 6 assessment completeness (never a security verdict).
    assessment_status = Column(String(50), nullable=True)  # not_started|running|completed|completed_with_gaps|failed
    assessment_completeness = Column(String(50), nullable=True)  # complete|partial|minimal|unknown
    assessment_snapshot_json = Column(JSON, nullable=True)  # config snapshot + reproducibility metadata

    # Phase 7 execution-platform state machine (created|queued|preflight|running|
    # validating|finalizing|completed|completed_with_gaps|blocked|failed|cancelled).
    state = Column(String(50), nullable=True, index=True)
    preflight_json = Column(JSON, nullable=True)  # real tool-readiness snapshot (never fabricated)
    queue_started_at = Column(DateTime, nullable=True)
    queue_waited_ms = Column(Integer, nullable=True)

    # Phase 8.5 product taxonomy: an assessment follows exactly one authorized
    # path -- "world_monitor" (a registered World Monitor deployment) or
    # "custom_target" (an operator-supplied authorized target). Persisted for
    # the record; enforcement remains the server-side scope guard.
    assessment_type = Column(String(50), nullable=True, index=True)
    # Phase 8.5 authorization acknowledgement: the operator asserted they are
    # authorized to assess the target. Audit record only -- the server-side
    # scope guard, never this flag, is the actual control.
    authorization_acknowledged = Column(Boolean, nullable=True)
    authorization_acknowledged_at = Column(DateTime, nullable=True)

    # Phase 9: schedule + attempt metadata (additive).  ``schedule_cadence`` is
    # an operator hint (e.g. "daily", "weekly", "manual"); retries/schedules are
    # traced in ``scan_attempts``, the {attempt_number, started_at, finished_at,
    # status, result} audit trail shared by interactive retries and scheduled
    # reruns (never fabricated: each row describes one real enqueued execution).
    schedule_cadence = Column(String(50), nullable=True)
    attempt_count = Column(Integer, nullable=True, default=1)
    # Phase 12: the schedule that created this scan (when it was not a manual
    # trigger).  NULL for interactive/retried scans -- a scan that was never
    # scheduled must never appear to be one.
    source_schedule_id = Column(Integer, ForeignKey("scan_schedules.id"), nullable=True)

    executions = relationship("ToolExecution", back_populates="scan", cascade="all, delete-orphan")
    scan_stages = relationship("ScanStage", back_populates="scan", cascade="all, delete-orphan")
    scan_events = relationship("ScanEvent", back_populates="scan", cascade="all, delete-orphan")
    attempts = relationship("ScanAttempt", back_populates="scan", cascade="all, delete-orphan")
    execution_runs = relationship("ScanExecution", back_populates="scan", cascade="all, delete-orphan")


class ToolResult(Base):
    """Per-tool execution record.

    Phase 4 persisted the coarse status + raw output.  Phase 5 adds execution
    telemetry (version, redacted command, timing, exit code, output sizes and
    how many observations the run parsed).  Commands stored here are always
    redacted: no secrets, tokens, cookies or credentials are persisted.
    """
    __tablename__ = "tool_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    tool_name = Column(String(50), nullable=False)  # "nmap", "nuclei", "subfinder", etc.
    status = Column(String(50), default="Pending")  # "Running", "Completed", "Failed"
    raw_output = Column(Text, default="")
    tool_version = Column(String(100), nullable=True)
    command_redacted = Column(Text, nullable=True)  # argument list with secrets redacted
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    exit_code = Column(Integer, nullable=True)
    duration_ms = Column(Integer, nullable=True)
    stdout_size = Column(Integer, nullable=True)
    stderr_size = Column(Integer, nullable=True)
    parsed_observations = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    scan = relationship("Scan", back_populates="tool_results")


class Vulnerability(Base):
    """A persisted security finding.

    Phase 3: a finding is never fabricated.  Every finding carries a rule_id,
    a triage state, and the evidence trail (human-readable ``evidence`` text
    plus the ids of the persisted ``Observation`` rows it was derived from).
    The chain finding -> evidence -> observation -> tool -> scan -> authorized
    target is therefore fully traceable in the database.
    """
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    title = Column(String(255), nullable=False)
    severity = Column(String(50), nullable=False)  # "Critical", "High", "Medium", "Low", "Info"
    description = Column(Text, nullable=False)
    remediation = Column(Text, nullable=True)
    cve = Column(String(100), nullable=True)
    cvss = Column(Float, nullable=True)
    owasp = Column(String(100), nullable=True)
    mitre = Column(String(100), nullable=True)
    cwe = Column(String(100), nullable=True)
    target = Column(String(255), nullable=True)  # URL/IP where it was found
    proof_of_concept = Column(Text, nullable=True)
    rule_id = Column(String(100), nullable=True)  # deterministic rule that produced this finding
    dedup_key = Column(String(255), nullable=True)  # stable identity used for duplicate suppression
    confidence = Column(String(20), nullable=True)  # Phase 3: "intermediate" | "confirmed"; Phase 5: LOW/MEDIUM/HIGH/CONFIRMED
    state = Column(String(50), nullable=False, default="NEW")  # NEW/CONFIRMED/FALSE_POSITIVE/DUPLICATE/ACCEPTED_RISK/RESOLVED
    # Phase 5 assessment metadata (all optional; existing Phase 3 rows remain valid).
    category = Column(String(100), nullable=True)  # vulnerability class, e.g. "authorization", "xss"
    endpoint = Column(String(512), nullable=True)  # normalized endpoint the finding concerns
    http_method = Column(String(20), nullable=True)  # GET/POST/...
    source_test = Column(String(100), nullable=True)  # security test id that produced the candidate
    source_tool = Column(String(100), nullable=True)  # observation-producing tool/probe
    validation_reason = Column(Text, nullable=True)  # deterministic reason for confirm/reject
    impact = Column(Text, nullable=True)  # documented impact statement
    evidence = Column(Text, nullable=True)  # human-readable support trail for the finding
    evidence_observation_ids = Column(JSON, nullable=True)  # ids of supporting Observation rows
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)

    # Phase 6 finding lifecycle + reporting (all optional/nullable).
    # status: candidate|validated|confirmed|rejected|duplicate|accepted|remediated|reopened
    status = Column(String(50), nullable=False, default="confirmed", index=True)
    affected_component = Column(String(100), nullable=True)  # e.g. "backend/api", "tls", "oauth"
    parameter = Column(String(255), nullable=True)
    cvss_version = Column(String(10), nullable=True)  # "3.1" when a vector is present
    cvss_vector = Column(String(255), nullable=True)  # full CVSS vector, never fabricated
    cvss_score = Column(Float, nullable=True)  # deterministic base score derived from the vector
    business_impact = Column(Text, nullable=True)
    technical_impact = Column(Text, nullable=True)
    impact_details = Column(JSON, nullable=True)  # structured technical/business impact factors
    remediation_details = Column(JSON, nullable=True)  # summary/technical_fix/configuration_fix/validation_steps/regression_test
    references_json = Column(JSON, nullable=True)  # deterministic reference list
    fingerprint = Column(String(64), nullable=True, index=True)  # finding identity for dedup/control
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)

    # Phase 7 cross-scan tracking (which scan first/last observed this finding).
    first_scan_id = Column(Integer, nullable=True)
    last_scan_id = Column(Integer, nullable=True)
    occurrence_count = Column(Integer, nullable=True, default=1)

    # Phase 9 asset provenance (additive): which persisted asset the finding
    # concerns, plus the CVE correlation state.  ``cve_status`` distinguishes
    # an observed CVE from one merely correlated by fingerprint.
    endpoint_asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True, index=True)
    cve_status = Column(String(20), nullable=True)  # observed | potentially_affected | confirmed

    # Phase 10.6 verification engine state (additive, default "unverified"):
    # flips to "verified"/"failed"/"not_applicable" only after the deterministic
    # re-check re-ran over the persisted observations for this finding.  A
    # verified state therefore always traces back to at least one
    # ``verifications`` row.
    verification_state = Column(String(30), nullable=False, default="unverified")

    scan = relationship("Scan", back_populates="vulnerabilities")
    evidence_records = relationship("FindingEvidence", back_populates="finding", cascade="all, delete-orphan")
    status_history = relationship("FindingStatusHistory", back_populates="finding", cascade="all, delete-orphan")
    endpoint_asset = relationship("Asset", foreign_keys=[endpoint_asset_id])


class Observation(Base):
    """A single, plugin-faithful factual observation captured by a real tool.

    Observations are the only accepted source of evidence: findings are derived
    exclusively from rows here.  ``kind`` names what was measured (e.g.
    ``dns_record``, ``tcp_connect``, ``http_response``), ``subject`` is the
    host/endpoint it measured, ``data_json`` holds the structured facts and
    ``raw_output`` the verbatim evidence snippet (response headers, resolved IP,
    DNS error, ...).  A probe that could not complete is recorded as an
    observation too (e.g. ``dns_error``, ``http_error``) so "nothing to report"
    is itself evidenced rather than silently dropped.

    Phase 5 enriches each observation with an explicit ``observation_type``,
    the owning ``user_id`` (denormalized so isolation can be queried directly),
    the normalized ``target``/``asset``, an optional structured
    ``request_json``/``response_json`` pair (headers redacted before storage),
    ``fingerprint`` for stable deduplication, and a ``status``/``source``.
    """
    __tablename__ = "observations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    tool_name = Column(String(50), nullable=False)  # which real tool/probe captured it
    kind = Column(String(50), nullable=False)
    subject = Column(String(255), nullable=False)  # host / endpoint the fact concerns
    data_json = Column(JSON, default=dict)
    raw_output = Column(Text, default="")
    # Phase 5 assessment fields (all optional/nullable for Phase 3 compatibility).
    user_id = Column(String(255), nullable=True)  # owner of the scan (denormalized)
    target = Column(String(255), nullable=True)  # normalized authorized target
    asset = Column(String(255), nullable=True)  # host/asset the observation belongs to
    observation_type = Column(String(50), nullable=True)  # see app.observations.types
    source = Column(String(100), nullable=True)  # e.g. "external_tool", "http_client", "stdlib_probe"
    tool_version = Column(String(100), nullable=True)
    request_json = Column(JSON, nullable=True)  # structured HTTP request (redacted)
    response_json = Column(JSON, nullable=True)  # structured HTTP response (redacted)
    metadata_json = Column(JSON, nullable=True)
    fingerprint = Column(String(64), nullable=True)  # stable SHA-256 of the observation identity
    status = Column(String(50), nullable=True)  # observed | error | skipped | ...
    observed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Phase 9: link the observation onto the project's asset graph (additive).
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True, index=True)

    # Phase 10.4: provenance -- which real tool-execution row produced this
    # observation (additive).  NULL means the observation came from a path that
    # does not create a ToolExecution row (e.g. the Phase 5 assessment engine's
    # native HTTP observations), which is honest: lineage says exactly what ran.
    tool_execution_id = Column(Integer, ForeignKey("tool_executions.id"),
                               nullable=True, index=True)

    scan = relationship("Scan", back_populates="observations")
    graph_asset = relationship("Asset", foreign_keys=[asset_id])


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    title = Column(String(255), nullable=False)
    pdf_content = Column(LargeBinary, nullable=True)  # Store report files or mock bytes
    markdown_content = Column(Text, nullable=True)
    json_content = Column(JSON, nullable=True)
    html_content = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    scan = relationship("Scan", back_populates="reports")


class ChatHistory(Base):
    __tablename__ = "chat_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    role = Column(String(50), nullable=False)  # "user", "assistant"
    message = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    scan = relationship("Scan", back_populates="chats")


class AssessmentTest(Base):
    """Deterministic record of one planned/executed security test on a scan.

    Phase 5 planning persists every test the planner considered so coverage is
    auditable: which tests were planned, applicable, skipped (and exactly why),
    executed, validated, or failed.  ``reason`` is always a concrete,
    deterministic explanation (never an LLM rationale).  A test is only counted
    as executed when it actually ran, and only counted as validated when the
    validator reached a confirmed/rejected verdict.
    """
    __tablename__ = "assessment_tests"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    test_id = Column(String(100), nullable=False)  # stable test identifier, e.g. "http.security_headers"
    name = Column(String(255), nullable=False)
    category = Column(String(100), nullable=False)  # vulnerability class, e.g. "xss", "authorization"
    status = Column(String(50), nullable=False, default="planned")
    # planned | not_applicable | skipped | executed | validated | failed | rejected
    reason = Column(Text, nullable=True)  # deterministic reason for the status
    target = Column(String(255), nullable=True)
    endpoint = Column(String(512), nullable=True)
    http_method = Column(String(20), nullable=True)
    active = Column(Boolean, default=False)  # True when the test mutates state
    required_observations = Column(JSON, nullable=True)  # observation types the test consumed
    required_capabilities = Column(JSON, nullable=True)  # tool/native capabilities required
    observation_ids = Column(JSON, nullable=True)  # observations produced by this test
    finding_ids = Column(JSON, nullable=True)  # findings created/confirmed by this test
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    scan = relationship("Scan", back_populates="assessment_tests")


class FindingEvidence(Base):
    """Structured evidence backing a finding.

    Each record links a finding to the observation(s) that prove it and stores
    the expected-vs-actual security-property comparison.  ``request_json`` and
    ``response_json`` are always redacted before persistence (no cookies,
    Authorization headers, API keys or tokens are ever stored in cleartext).
    """
    __tablename__ = "finding_evidence"

    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=False)
    observation_id = Column(Integer, ForeignKey("observations.id"), nullable=True)
    evidence_type = Column(String(50), nullable=False)  # request|response|comparison|header|tool_output|certificate|authorization_difference
    request_json = Column(JSON, nullable=True)
    response_json = Column(JSON, nullable=True)
    expected = Column(Text, nullable=True)
    actual = Column(Text, nullable=True)
    security_boundary = Column(Text, nullable=True)
    redaction_status = Column(String(50), default="redacted")
    # Phase 6 evidence integrity: hashes over the redacted payload so accidental
    # mutation is detectable; bounded body capture metadata.
    request_hash = Column(String(64), nullable=True)
    response_hash = Column(String(64), nullable=True)
    original_size = Column(Integer, nullable=True)  # observed response body size (bytes)
    captured_size = Column(Integer, nullable=True)  # bytes actually persisted
    truncated = Column(Boolean, nullable=True)  # True when the body was bounded
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    finding = relationship("Vulnerability", back_populates="evidence_records")
    observation = relationship("Observation")


class FindingStatusHistory(Base):
    """Immutable audit trail of a finding's lifecycle transitions.

    Every status change (candidate -> confirmed -> remediated -> reopened, or any
    manual triage transition) appends a row here.  Historical state is never
    overwritten or deleted.
    """
    __tablename__ = "finding_status_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=False, index=True)
    from_status = Column(String(50), nullable=False)
    to_status = Column(String(50), nullable=False)
    actor = Column(String(255), nullable=False, default="system")
    reason = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, index=True)

    finding = relationship("Vulnerability", back_populates="status_history")


class ReportExport(Base):
    """Persisted, reproducibility metadata for a generated assessment report.

    The report body is regenerated deterministically from persisted state; this
    row records what was generated, when, and against which assessment version
    (registry + configuration fingerprints) so the report is reproducible.
    """
    __tablename__ = "report_exports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    user_id = Column(String(255), nullable=True)
    format = Column(String(20), nullable=False)  # json|markdown
    content_hash = Column(String(64), nullable=True)  # SHA-256 of the rendered payload
    registry_fingerprint = Column(String(64), nullable=True)
    config_fingerprint = Column(String(64), nullable=True)
    content_length = Column(Integer, nullable=True)
    generated_at = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    content_json = Column(JSON, nullable=True)
    content_markdown = Column(Text, nullable=True)
    # Phase 9: the HTML and PDF projections are persisted too, so any export
    # format can be re-served or audited byte-for-byte.
    content_html = Column(Text, nullable=True)
    content_pdf = Column(LargeBinary, nullable=True)

    scan = relationship("Scan", back_populates="report_exports")


# ---------------------------------------------------------------------------
# Phase 7 execution platform
#
# These tables give a scan a full, honest execution trail: what preflight
# found (ToolReadiness), how every tool actually ran (ToolExecution), which
# stage of the pipeline it belonged to (ScanStage), the typed event stream
# (ScanEvent), every deterministic validator verdict (FindingValidation), the
# finding <-> observation linkage used for provenance (FindingObservationLink)
# and the advisory record (MLInference).  Nothing in here is ever fabricated:
# a row is only written after the real artifact it describes happened.
# ---------------------------------------------------------------------------
class ToolReadiness(Base):
    """Real preflight result for one tool on one scan.

    ``status`` is one of: installed | missing | disabled | adapter_unavailable.
    ``executable``/``version`` come from real PATH/version probes (see
    app.tools.inventory); a missing binary is recorded as missing, never as
    available.  This is the readiness answer the pipeline gates on.
    """
    __tablename__ = "tool_readiness"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    tool = Column(String(50), nullable=False)
    status = Column(String(50), nullable=False)  # installed|missing|disabled|adapter_unavailable
    executable = Column(String(500), nullable=True)
    version = Column(String(200), nullable=True)
    adapter = Column(String(50), nullable=True)  # external|legacy|probe|none
    category = Column(String(50), nullable=True)  # recon|dns|service|http|vulnerability|probe
    enabled = Column(Boolean, default=True)  # operator requested this tool
    reason = Column(String(255), nullable=True)
    duration_ms = Column(Integer, nullable=True)
    checked_at = Column(DateTime, default=datetime.datetime.utcnow)

    scan = relationship("Scan")


class ScanExecution(Base):
    """Phase 10.3 execution batch: how one scan's plan was actually run.

    Parallel scheduler support (additive).  One row per real execution of a
    scan plan records the scheduling decision (sequential vs parallel), the
    bounded concurrency applied, the ordered plan that was executed, and the
    honest per-state counters.  Nothing here is fabricated: the counters are
    real increments observed from tool results, and ``strategy`` reflects the
    concurrency bound the pipeline actually applied.
    """
    __tablename__ = "scan_executions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    strategy = Column(String(20), nullable=False, default="sequential")  # sequential|parallel
    max_parallel_tools = Column(Integer, nullable=False, default=1)
    plan = Column(JSON, nullable=True)  # ordered [{"stage": ..., "tools": [...]}]
    planned_tools = Column(Integer, nullable=False, default=0)
    started_tools = Column(Integer, nullable=False, default=0)
    completed_tools = Column(Integer, nullable=False, default=0)
    failed_tools = Column(Integer, nullable=False, default=0)
    skipped_tools = Column(Integer, nullable=False, default=0)
    status = Column(String(20), nullable=False, default="queued")  # queued|running|completed|cancelled|failed
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    duration_ms = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    scan = relationship("Scan", back_populates="execution_runs")


class ToolExecution(Base):
    """One real attempt (or skip) of an external tool on a scan.

    Holds process telemetry that ToolResult does not: exact redacted command,
    bounded output sizes (stdout/stderr are never stored unbounded here), how
    many parsed observations the run produced, cancellation state and the
    attempt index inside a bounded retry loop.  ``status`` is terminal and
    honest: completed | failed | timeout | not_installed | parse_failed |
    skipped | cancelled.
    """
    __tablename__ = "tool_executions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    stage = Column(String(50), nullable=False)  # Phase 7 pipeline stage name
    tool = Column(String(50), nullable=False)
    adapter = Column(String(50), nullable=True)  # adapter implementation used
    attempt = Column(Integer, nullable=False, default=1)
    status = Column(String(50), nullable=False, default="queued")
    executable = Column(String(500), nullable=True)
    tool_version = Column(String(200), nullable=True)
    target = Column(String(255), nullable=True)
    command_redacted = Column(Text, nullable=True)
    exit_code = Column(Integer, nullable=True)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    duration_ms = Column(Integer, nullable=True)
    stdout_size = Column(Integer, nullable=True)
    stderr_size = Column(Integer, nullable=True)
    stdout_truncated = Column(Boolean, default=False)
    stderr_truncated = Column(Boolean, default=False)
    parsed_observations = Column(Integer, default=0)
    cancellation_state = Column(String(50), nullable=True)  # request sent|terminated|observed
    termination_reason = Column(String(255), nullable=True)
    error_code = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    scan = relationship("Scan", back_populates="executions")


class ScanStage(Base):
    """Progress ledger for one Phase 7 pipeline stage on one scan.

    ``status`` is queued|running|completed|failed|skipped|blocked.  Counters are
    real increments observed by the pipeline; a stage with no work can never
    report completed tool runs.
    """
    __tablename__ = "scan_stages"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    name = Column(String(50), nullable=False)  # Phase 7 stage name (PRECHECK, ...)
    order = Column(Integer, nullable=False, default=0)
    status = Column(String(50), nullable=False, default="queued")
    reason = Column(Text, nullable=True)
    tools = Column(JSON, nullable=True)  # tool names planned for this stage
    tests_executed = Column(Integer, nullable=True, default=0)
    observations = Column(Integer, nullable=True, default=0)
    candidates = Column(Integer, nullable=True, default=0)
    confirmed_findings = Column(Integer, nullable=True, default=0)
    errors = Column(JSON, nullable=True)  # {tool: [error strings]} real failures only
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    duration_ms = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    scan = relationship("Scan", back_populates="scan_stages")


class ScanEvent(Base):
    """Ordered, typed event stream for a scan (Phase 7 live dashboarding).

    Each row is a real, completed event: state transitions, stage lifecycle,
    tool start/finish, preflight results, coverage/progress changes, candidate
    and validated-finding updates, and the terminal resolution.  The stream is
    append-only and id-ordered so a client can replay from any cursor.
    """
    __tablename__ = "scan_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    event_type = Column(String(50), nullable=False)  # state|stage|tool|preflight|coverage|finding|validation|done|error
    data = Column(JSON, nullable=True)
    seq = Column(Integer, nullable=False, default=0)  # monotonic per-scan counter
    created_at = Column(DateTime, default=datetime.datetime.utcnow, index=True)

    scan = relationship("Scan", back_populates="scan_events")


class FindingValidation(Base):
    """One deterministic validator verdict for a finding candidate.

    Written alongside finding persistence: every candidate that reached a
    validator is recorded (confirmed or rejected), with the validator id, the
    security property/condition that was checked, and the exact reason.  This
    makes the "found then re-checked" chain auditable end to end.
    """
    __tablename__ = "finding_validations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=True)  # present when confirmed
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    validator_id = Column(String(100), nullable=False)  # e.g. "injection.xss.reflected"
    status = Column(String(50), nullable=False)  # confirmed | rejected
    condition = Column(Text, nullable=True)  # security property that was checked
    reason = Column(Text, nullable=True)
    expected = Column(Text, nullable=True)
    actual = Column(Text, nullable=True)
    security_boundary = Column(Text, nullable=True)
    confidence = Column(String(20), nullable=True)
    observation_id = Column(Integer, ForeignKey("observations.id"), nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    duration_ms = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    scan = relationship("Scan")
    finding = relationship("Vulnerability")


class Verification(Base):
    """One deterministic re-check run for a finding candidate (Phase 10.6).

    Written by the verification engine, which **never** issues a new network
    request: it re-runs the deterministic rule over the SAME persisted
    ``Observation`` rows the finding was derived from, and records whether the
    candidate is reproduced (``verified``), not reproduced (``failed``), or
    cannot be re-checked because there is no supporting observation
    (``not_applicable``).  Only a ``verified`` row permits
    ``Vulnerability.verification_state`` to be set to ``verified``.

    The verification engine is therefore an auditable, replayable re-proof: the
    verification_state on a finding always traces back to at least one row here,
    and rows are append-only so re-runs accumulate without rewriting history.
    """
    __tablename__ = "verifications"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    finding_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=True, index=True)
    # method of re-check, e.g. "deterministic.rule" (the only method today).
    method = Column(String(50), nullable=False)
    status = Column(String(30), nullable=False)  # verified | failed | not_applicable
    rule_id = Column(String(100), nullable=True)  # rule that was re-run
    condition = Column(Text, nullable=True)  # what the re-check asserted
    reason = Column(Text, nullable=True)
    observation_ids = Column(JSON, nullable=True)  # persisted observations re-checked
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    duration_ms = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    scan = relationship("Scan")
    finding = relationship("Vulnerability")


class FindingObservationLink(Base):
    """Explicit finding <-> observation provenance edge (Phase 7).

    Backs the JSON ``evidence_observation_ids`` list with a first-class
    relation so provenance is joinable and never accidentally dropped.
    """
    __tablename__ = "finding_observation_links"

    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=False, index=True)
    observation_id = Column(Integer, ForeignKey("observations.id"), nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    finding = relationship("Vulnerability")
    observation = relationship("Observation")


class MLInference(Base):
    """Advisory record for one scan.

    This platform ships no model, so ``status`` is always ``advisory_only`` and
    the payload is the deterministic coverage-gap advisory produced by
    app.ml.advisory.  The row marks explicitly that no model prediction entered
    the pipeline -- an ML layer can never silently upgrade evidence.
    """
    __tablename__ = "ml_inferences"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    model_name = Column(String(100), nullable=True)  # None: no model in play
    model_version = Column(String(100), nullable=True)
    model_type = Column(String(50), nullable=True)  # None → deterministic baseline
    feature_schema_version = Column(String(50), nullable=True)
    training_status = Column(String(50), nullable=True)  # none|untrained|trained
    input_source = Column(String(50), nullable=True)  # persisted scan state
    status = Column(String(50), nullable=False, default="advisory_only")
    advisory_json = Column(JSON, nullable=True)
    generated_at = Column(DateTime, default=datetime.datetime.utcnow)

    scan = relationship("Scan")


# ---------------------------------------------------------------------------
# Phase 8 World Monitor integration
#
# A WorldMonitorTarget is an explicitly configured, authorized World Monitor
# deployment belonging to one project.  Its status is never ``secure`` or
# ``insecure``: connectivity is assessed (not_configured / checking /
# reachable / unavailable / partially_discovered / discovered) while security
# posture comes only from the assessment findings derived from its real
# observations.  The API-endpoint table is the normalized inventory produced by
# OpenAPI/API discovery; every endpoint that later yields an observation keeps
# its observation_id so the evidence chain stays traceable.
# ---------------------------------------------------------------------------
WORLD_MONITOR_STATUS_NOT_CONFIGURED = "not_configured"
WORLD_MONITOR_STATUS_CHECKING = "checking"
WORLD_MONITOR_STATUS_REACHABLE = "reachable"
WORLD_MONITOR_STATUS_UNAVAILABLE = "unavailable"
WORLD_MONITOR_STATUS_PARTIALLY_DISCOVERED = "partially_discovered"
WORLD_MONITOR_STATUS_DISCOVERED = "discovered"

WORLD_MONITOR_STATUSES = (
    WORLD_MONITOR_STATUS_NOT_CONFIGURED,
    WORLD_MONITOR_STATUS_CHECKING,
    WORLD_MONITOR_STATUS_REACHABLE,
    WORLD_MONITOR_STATUS_UNAVAILABLE,
    WORLD_MONITOR_STATUS_PARTIALLY_DISCOVERED,
    WORLD_MONITOR_STATUS_DISCOVERED,
)


class WorldMonitorTarget(Base):
    """One authorized World Monitor deployment configured for assessment.

    ``base_url`` is the health-check root; ``api_base_url``/``openapi_url`` are
    optional and only ever taken from explicit configuration (never guessed).
    ``status`` reflects connectivity/discovery (see constants above);
    ``health_json``/``discovery_json`` hold the real probe results and
    ``discovered_version`` any version metadata observed at runtime.
    """
    __tablename__ = "world_monitor_targets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False, index=True)
    base_url = Column(String(255), nullable=False)
    api_base_url = Column(String(255), nullable=True)
    openapi_url = Column(String(255), nullable=True)
    status = Column(String(50), nullable=False, default=WORLD_MONITOR_STATUS_NOT_CONFIGURED)
    last_checked_at = Column(DateTime, nullable=True)
    last_discovery_at = Column(DateTime, nullable=True)
    discovered_version = Column(String(100), nullable=True)
    health_json = Column(JSON, nullable=True)
    discovery_json = Column(JSON, nullable=True)
    error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, nullable=True)

    project = relationship("Project")
    api_endpoints = relationship("WorldMonitorAPIEndpoint", back_populates="target",
                                 cascade="all, delete-orphan")


class WorldMonitorAPIEndpoint(Base):
    """One normalized endpoint discovered from a World Monitor deployment.

    Only real, observed endpoints are stored.  ``source`` records how the
    endpoint was found (openapi | frontend | api_base | base_url).  When the
    endpoint is later probed during a scan, ``observation_id`` links it to the
    persisted Observation row that backs the evidence chain.
    """
    __tablename__ = "world_monitor_api_endpoints"

    id = Column(Integer, primary_key=True, autoincrement=True)
    target_id = Column(Integer, ForeignKey("world_monitor_targets.id"), nullable=False, index=True)
    method = Column(String(10), nullable=False)
    path = Column(String(512), nullable=False)
    operation_id = Column(String(255), nullable=True)
    tags = Column(JSON, nullable=True)
    source = Column(String(50), nullable=False, default="openapi")
    authentication_hint = Column(String(255), nullable=True)
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    observation_id = Column(Integer, ForeignKey("observations.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    target = relationship("WorldMonitorTarget", back_populates="api_endpoints")
    observation = relationship("Observation")


class ScanSchedule(Base):
    """One operator-defined recurrent scan (Phase 12, additive).

    A schedule is a recurrence *definition*, not a scan: each due execution
    creates a fresh ``Scan`` row carrying ``source_schedule_id`` and a
    ``ScanAttempt`` with ``trigger='schedule'``, so a scheduled run is as
    traceable as a manual one.  ``next_run_at`` is derived deterministically
    from ``cadence`` + ``interval``; it is never free-formed.
    """
    __tablename__ = "scan_schedules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(255), ForeignKey("users.id"), nullable=False, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False, index=True)
    name = Column(String(255), nullable=True)
    target = Column(String(255), nullable=False)
    cadence = Column(String(50), nullable=False, default="daily")  # hourly | daily | weekly
    interval = Column(Integer, nullable=False, default=1)  # every N cadence units
    enabled = Column(Boolean, nullable=False, default=True)
    next_run_at = Column(DateTime, nullable=False)
    last_run_at = Column(DateTime, nullable=True)
    last_run_status = Column(String(50), nullable=True)  # queued | running | completed | failed | cancelled
    last_scan_id = Column(Integer, nullable=True)
    config = Column(JSON, nullable=True)  # scan configuration snapshot used by scheduled runs
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, nullable=True)

    project = relationship("Project")


class ScanAttempt(Base):
    """One real enqueued execution of a scan (Phase 9, additive).

    Every time a scan runs -- initial trigger, an interactive retry, or a
    scheduled rerun -- a row is appended describing that one execution.  The
    counter on ``Scan`` is derived from these rows, so retries and schedules
    never hide behind a single ``scans`` row.  Status vocabulary mirrors the
    scan lifecycle (queued/running/completed/partial/failed/cancelled).
    """
    __tablename__ = "scan_attempts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    attempt_number = Column(Integer, nullable=False, default=1)
    trigger = Column(String(50), nullable=True)  # manual | retry | schedule
    status = Column(String(50), nullable=False, default="queued")
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    result = Column(JSON, nullable=True)  # {state, coverage, findings, error}
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    scan = relationship("Scan", back_populates="attempts")
