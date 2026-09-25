from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.tools.inventory import tool_inventory, tool_health_summary
from app.tools.manifest import build_manifests
from app.config import settings
from database.connection import get_db
from database.models import User

router = APIRouter(prefix="/tools", tags=["tools"])


@router.get("/inventory")
def get_tool_inventory(user: User = Depends(get_current_user)):
    """Real tool inventory: installed binaries + version + category.

    Reporting is honest: every entry reflects an actual ``shutil.which``
    probe on the host, never an assumption about what should be available.
    Each entry carries a ``health_status``: installed | missing |
    version_unknown | permission_error.
    """
    return {
        "tools": tool_inventory(),
        "simulation_mode": settings.simulation_mode,
        "simulated": settings.simulation_mode,
    }


@router.get("/health")
def get_tool_health(user: User = Depends(get_current_user)):
    """Health snapshot with the Phase 10.2 status vocabulary (+ counts)."""
    return tool_health_summary()


@router.get("/manifest")
def get_tool_manifest(user: User = Depends(get_current_user)):
    """Canonical scanner manifests merged with the real install state.

    Each entry is the static declaration (capabilities, category, adapter
    kind, opt-in gating, default options) plus the live health of the binary.
    Capabilities are only reported as available when the tool is operational.
    """
    return {"manifests": build_manifests()}


@router.get("/status")
def get_tool_status(user: User = Depends(get_current_user)):
    """Readiness status of every scanner the Phase 7 pipeline can schedule.

    Buckets tools into installed / missing / probes so the UI can render a
    health panel and a preflight preview before a scan is created.
    """
    tools = tool_inventory()
    installed = [t for t in tools if t["installed"]]
    missing = [t for t in tools if not t["installed"]]
    return {
        "total": len(tools),
        "installed_count": len(installed),
        "missing_count": len(missing),
        "installed": installed,
        "missing": missing,
        "simulation_mode": settings.simulation_mode,
    }


@router.get("/executions")
def get_tool_executions(user: User = Depends(get_current_user),
                        db: Session = Depends(get_db)):
    """Real per-tool execution ledger across the user's scans.

    Every number is a persisted ``ToolExecution`` row on a scan the user owns
    -- never an inventory assumption about whether a tool "probably ran".
    Tools with zero executions appear with honest zero counts.  Status counts
    use the terminal vocabulary completed | failed | timeout | not_installed |
    parse_failed | skipped | cancelled.
    """
    from collections import defaultdict

    from database.models import Project, Scan, ToolExecution

    owned_project_ids = [p.id for p in db.query(Project).filter(Project.user_id == user.id).all()]
    scan_ids = (
        [r[0] for r in db.query(Scan.id).filter(Scan.project_id.in_(owned_project_ids)).all()]
        if owned_project_ids else []
    )

    execution_statuses = ("completed", "failed", "timeout", "not_installed",
                          "parse_failed", "skipped", "cancelled")

    def _empty(tool: str, category: str) -> dict:
        return {
            "tool": tool,
            "category": category,
            "executions_total": 0,
            "statuses": {s: 0 for s in execution_statuses},
            "observations_produced": 0,
            "last_execution_at": None,
            "last_status": None,
            "scans_touched": 0,
        }

    per: dict[str, dict] = {}
    if scan_ids:
        rows = (
            db.query(ToolExecution)
            .filter(ToolExecution.scan_id.in_(scan_ids))
            .all()
        )
        for r in rows:
            agg = per.setdefault(r.tool, _empty(r.tool, "probe"))
            agg["executions_total"] += 1
            agg["statuses"][r.status] = agg["statuses"].get(r.status, 0) + 1
            agg["observations_produced"] += int(r.parsed_observations or 0)
            scanned_ids = agg.setdefault("_scans", set())
            scanned_ids.add(r.scan_id)
            agg["scans_touched"] = len(scanned_ids)
            ts = r.finished_at or r.created_at
            if ts is not None and (agg["last_execution_at"] is None
                                   or ts.isoformat() > agg["last_execution_at"]):
                agg["last_execution_at"] = ts.isoformat()
                agg["last_status"] = r.status
        for agg in per.values():
            del agg["_scans"]
            agg["statuses"] = {k: agg["statuses"].get(k, 0) for k in execution_statuses}

    for inv in tool_inventory():
        if inv["tool"] not in per:
            per[inv["tool"]] = _empty(inv["tool"], inv["category"])
        else:
            per[inv["tool"]]["category"] = inv["category"]

    totals = {s: 0 for s in execution_statuses}
    for agg in per.values():
        for s in execution_statuses:
            totals[s] += agg["statuses"][s]

    return {
        "tools": sorted(per.values(), key=lambda t: (-t["executions_total"], t["tool"])),
        "totals": {
            "executions": sum(a["executions_total"] for a in per.values()),
            "observations_produced": sum(a["observations_produced"] for a in per.values()),
            **totals,
        },
        "simulation_mode": settings.simulation_mode,
    }


@router.post("/refresh")
def refresh_tool_status(user: User = Depends(get_current_user)):
    """Re-merge fresh PATH entries and re-probe every scanner.

    Call this after installing a scanner at runtime; it makes the new binary
    visible to the pipeline without a backend restart.
    """
    from app.tools.scanner_tools import refresh_tool_path
    refresh_tool_path()
    tools = tool_inventory()
    return {
        "refreshed": True,
        "tools": tools,
        "installed_count": sum(1 for t in tools if t["installed"]),
        "simulation_mode": settings.simulation_mode,
    }