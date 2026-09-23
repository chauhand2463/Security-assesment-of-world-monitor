"""World Monitor integration endpoints (Phase 8).

The World Monitor deployment is treated as another *authorized target* of the
platform: it belongs to exactly one project, its probe URLs are confined to the
project's authorized scope, and every result is persisted raw (health_json /
discovery_json) so downstream assessment is derived from real observations.

Connectivity states follow the Phase 8 vocabulary -- not_configured / checking /
reachable / unavailable / partially_discovered / discovered -- and never carry a
``secure``/``insecure`` verdict.  Authentication and ownership are enforced with
the same user -> project chain used everywhere else; a target that is not owned
by the caller is indistinguishable from one that does not exist (404).
"""
from __future__ import annotations

import datetime
import urllib.parse

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.http.fingerprints import host_of
from app.integrations.world_monitor import WorldMonitorProvider
from app.integrations.world_monitor.discovery import TargetConfig
from app.integrations.world_monitor import models as wm_models
from database.connection import get_db
from database.models import (
    Asset,
    Project,
    User,
    WorldMonitorAPIEndpoint,
    WorldMonitorTarget,
    WORLD_MONITOR_STATUS_DISCOVERED,
    WORLD_MONITOR_STATUS_NOT_CONFIGURED,
    WORLD_MONITOR_STATUS_PARTIALLY_DISCOVERED,
    WORLD_MONITOR_STATUS_REACHABLE,
    WORLD_MONITOR_STATUS_CHECKING,
    WORLD_MONITOR_STATUS_UNAVAILABLE,
)

router = APIRouter(prefix="/world-monitor", tags=["world-monitor"])


def _valid_url(url: str) -> bool:
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    return parts.scheme in ("http", "https") and bool(parts.netloc) and parts.netloc.count(":") <= 1


class WorldMonitorTargetCreate(BaseModel):
    """Explicit, authorized World Monitor configuration.  Nothing is guessed.

    ``api_base_url``/``openapi_url`` are optional and only honoured when they
    point at the same deployment host as ``base_url`` (defense against a
    misconfigured Cross-Target fetch).
    """
    base_url: str
    api_base_url: str | None = None
    openapi_url: str | None = None

    @field_validator("base_url", "api_base_url", "openapi_url")
    @classmethod
    def _clean_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not _valid_url(value):
            raise ValueError("must be an http(s) URL")
        return value.rstrip("/")


def _owned_target(db: Session, user: User, target_id: int) -> WorldMonitorTarget:
    """Fetch a target only when it belongs to one of the caller's projects."""
    target = db.query(WorldMonitorTarget).filter(WorldMonitorTarget.id == target_id).first()
    if target is None:
        raise HTTPException(status_code=404, detail="World Monitor target not found.")
    owner = (db.query(Project)
             .filter(Project.id == target.project_id, Project.user_id == user.id)
             .first())
    if owner is None:
        raise HTTPException(status_code=404, detail="World Monitor target not found.")
    return target


def _target_scope_guard(db: Session, project: Project, target: WorldMonitorTarget):
    """Scope guard confining WM probes to the deployment + project scope.

    Mirrors ``app.assess.engine._scope_guard``: the configured deployment hosts
    (base/api/openapi) are authorized, and so is the project's declared scope
    plus its discovered assets.  Everything else is refused before any socket
    is opened.
    """
    from app.core.auth import is_target_in_scope

    assets = db.query(Asset).filter(Asset.project_id == project.id).all()
    allowed_hosts = {host_of(u).lower() for u in
                     (target.base_url, target.api_base_url, target.openapi_url) if host_of(u)}

    def guard(url: str) -> bool:
        host = host_of(url)
        if not host:
            return False
        if host.lower() in allowed_hosts:
            return True
        return bool(project and is_target_in_scope(host, project, assets))

    return guard


def _endpoint_dict(e: WorldMonitorAPIEndpoint) -> dict:
    return {
        "id": e.id,
        "method": e.method,
        "path": e.path,
        "operation_id": e.operation_id,
        "tags": e.tags or [],
        "source": e.source,
        "authentication_hint": e.authentication_hint,
        "observation_id": e.observation_id,
        "first_seen": e.first_seen,
        "last_seen": e.last_seen,
    }


def _staleness(target: WorldMonitorTarget, db: Session) -> dict:
    """Surface probe-result age honestly (Phase 10.9).

    Staleness is a reported fact computed from the last persisted probe times
    versus a configurable threshold; it never triggers automatic re-probing.
    ``never_checked`` is the honest state for a target with no probe history.
    """
    from app.config import settings

    threshold = settings.world_monitor_stale_after_seconds or 3600
    now = datetime.datetime.utcnow()
    last_checked = target.last_checked_at
    last_discovery = target.last_discovery_at
    since_check = None
    since_discovery = None
    if last_checked is not None:
        since_check = max(0, int((now - last_checked).total_seconds()))
    if last_discovery is not None:
        since_discovery = max(0, int((now - last_discovery).total_seconds()))
    if last_checked is None:
        state = "never_checked"
    else:
        state = "stale" if since_check > threshold else "fresh"
    return {
        "state": state,
        "threshold_seconds": threshold,
        "seconds_since_last_check": since_check,
        "seconds_since_last_discovery": since_discovery,
    }


def _bridged_scan_ids(target: WorldMonitorTarget, db: Session) -> list[int]:
    """Scans that explicitly bridge to this target (Phase 10.9).

    The scan -> target bridge stays explicit and visible: any Scan whose
    ``scan_config`` carries ``world_monitor.target_id`` equal to this target is
    reported here.  Nothing is inferred from target name or URL heuristics.
    """
    from database.models import Scan

    rows = (
        db.query(Scan.id, Scan.scan_config)
        .filter(Scan.project_id == target.project_id)
        .all()
    )
    out = []
    for scan_id, config in rows:
        wm = (config or {}).get("world_monitor") if isinstance(config, dict) else None
        if isinstance(wm, dict) and wm.get("target_id") == target.id:
            out.append(scan_id)
    return sorted(out)


def _target_dict(target: WorldMonitorTarget, db: Session, include_inventory: bool = False) -> dict:
    payload = {
        "id": target.id,
        "project_id": target.project_id,
        "base_url": target.base_url,
        "api_base_url": target.api_base_url,
        "openapi_url": target.openapi_url,
        "status": target.status,
        "last_checked_at": target.last_checked_at,
        "last_discovery_at": target.last_discovery_at,
        "discovered_version": target.discovered_version,
        "health": target.health_json,
        "discovery": target.discovery_json,
        "error": target.error,
        "created_at": target.created_at,
        "updated_at": target.updated_at,
        "staleness": _staleness(target, db),
        "bridged_scans": _bridged_scan_ids(target, db),
        "api_endpoints_total": (
            db.query(WorldMonitorAPIEndpoint).filter(WorldMonitorAPIEndpoint.target_id == target.id).count()
        ),
    }
    if include_inventory:
        rows = (
            db.query(WorldMonitorAPIEndpoint)
            .filter(WorldMonitorAPIEndpoint.target_id == target.id)
            .order_by(WorldMonitorAPIEndpoint.id.asc())
            .all()
        )
        payload["api_endpoints"] = [_endpoint_dict(r) for r in rows]
    return payload


@router.post("/targets")
def create_target(payload: WorldMonitorTargetCreate, user: User = Depends(get_current_user),
                  db: Session = Depends(get_db)):
    """Register an authorized World Monitor deployment for assessment."""
    from app.core.auth import get_or_create_user_project

    project = get_or_create_user_project(db, user)
    allowed_hosts = {host_of(payload.base_url).lower()}
    for extra in (payload.api_base_url, payload.openapi_url):
        if extra and host_of(extra).lower() not in allowed_hosts:
            raise HTTPException(
                status_code=422,
                detail="api_base_url/openapi_url must point at the same deployment host as base_url.",
            )

    target = WorldMonitorTarget(
        project_id=project.id,
        base_url=payload.base_url,
        api_base_url=payload.api_base_url,
        openapi_url=payload.openapi_url,
        status=WORLD_MONITOR_STATUS_NOT_CONFIGURED,
    )
    db.add(target)
    db.commit()
    db.refresh(target)
    return _target_dict(target, db)


@router.get("/targets")
def list_targets(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """The caller's World Monitor deployments (scoped to their own project)."""
    from app.core.auth import get_user_projects

    project_ids = [p.id for p in get_user_projects(db, user)]
    if not project_ids:
        return []
    rows = (
        db.query(WorldMonitorTarget)
        .filter(WorldMonitorTarget.project_id.in_(project_ids))
        .order_by(WorldMonitorTarget.created_at.desc())
        .all()
    )
    return [_target_dict(r, db) for r in rows]


@router.get("/targets/{target_id}")
def get_target(target_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Full detail for one owned World Monitor target, including its inventory."""
    target = _owned_target(db, user, target_id)
    return _target_dict(target, db, include_inventory=True)


@router.delete("/targets/{target_id}")
def delete_target(target_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Remove a World Monitor target and its discovered inventory."""
    target = _owned_target(db, user, target_id)
    db.query(WorldMonitorAPIEndpoint).filter(WorldMonitorAPIEndpoint.target_id == target.id).delete()
    db.delete(target)
    db.commit()
    return {"deleted": True, "target_id": target_id}


@router.post("/targets/{target_id}/check")
def check_target(target_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Run one real health probe against the configured base URL.

    The result is persisted verbatim; it describes reachability and observed
    deployment metadata, never a security verdict.
    """
    target = _owned_target(db, user, target_id)
    project = db.query(Project).filter(Project.id == target.project_id).first()
    provider = WorldMonitorProvider(_target_scope_guard(db, project, target))

    target.status = WORLD_MONITOR_STATUS_CHECKING
    db.commit()

    health = provider.check_health(target.base_url)
    target.status = WORLD_MONITOR_STATUS_REACHABLE if health.reachable else WORLD_MONITOR_STATUS_UNAVAILABLE
    target.health_json = {
        "url": health.url,
        "reachable": health.reachable,
        "http_status": health.http_status,
        "elapsed_ms": round(health.elapsed_ms, 3) if health.elapsed_ms is not None else None,
        "server": health.server,
        "version_hint": health.version_hint,
        "detected_metadata": health.detected_metadata,
        "tls": None if health.tls is None else {
            "subject": health.tls.get("subject"),
            "issuer": health.tls.get("issuer"),
            "valid_after": health.tls.get("not_after"),
            "expired": health.tls.get("expired"),
        },
        "error": health.error,
        "checked_at": health.checked_at,
    }
    target.error = health.error
    target.last_checked_at = datetime.datetime.utcnow()
    target.updated_at = datetime.datetime.utcnow()
    db.commit()
    db.refresh(target)
    return _target_dict(target, db)


@router.post("/targets/{target_id}/discover")
def discover_target(target_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Run discovery: real health + API/OpenAPI probing against explicit config.

    The API-endpoint inventory is replaced with what was actually observed;
    unconfigured/unsupported sources are recorded as such, never guessed.
    """
    target = _owned_target(db, user, target_id)
    project = db.query(Project).filter(Project.id == target.project_id).first()
    guard = _target_scope_guard(db, project, target)
    provider = WorldMonitorProvider(guard)

    target.status = WORLD_MONITOR_STATUS_CHECKING
    db.commit()

    config = TargetConfig(
        base_url=target.base_url,
        api_base_url=target.api_base_url,
        openapi_url=target.openapi_url,
    )
    result = provider.discover(config)

    new_health = result.health
    target.health_json = None if new_health is None else {
        "url": new_health.url,
        "reachable": new_health.reachable,
        "http_status": new_health.http_status,
        "elapsed_ms": round(new_health.elapsed_ms, 3) if new_health.elapsed_ms is not None else None,
        "server": new_health.server,
        "version_hint": new_health.version_hint,
        "error": new_health.error,
        "checked_at": new_health.checked_at,
    }
    target.discovery_json = {
        "started_at": result.started_at,
        "finished_at": result.finished_at,
        "target_status": result.target_status,
        "openapi_status": result.openapi_status,
        "discovered_version": result.discovered_version,
        "step_count": len(result.steps),
        "endpoint_count": len(result.endpoints),
        "steps": [
            {
                "order": s.order,
                "source": s.source,
                "status": s.status,
                "detail": s.detail,
            }
            for s in result.steps
        ],
        "error": result.error,
    }
    target.error = result.error
    target.last_discovery_at = datetime.datetime.utcnow()
    target.last_checked_at = datetime.datetime.utcnow()

    if result.target_status == WORLD_MONITOR_STATUS_DISCOVERED:
        target.status = WORLD_MONITOR_STATUS_DISCOVERED
    elif result.target_status == WORLD_MONITOR_STATUS_PARTIALLY_DISCOVERED:
        target.status = WORLD_MONITOR_STATUS_PARTIALLY_DISCOVERED
    else:
        target.status = WORLD_MONITOR_STATUS_UNAVAILABLE
    target.discovered_version = result.discovered_version
    target.updated_at = datetime.datetime.utcnow()
    db.commit()

    db.query(WorldMonitorAPIEndpoint).filter(WorldMonitorAPIEndpoint.target_id == target.id).delete()
    db.flush()
    now = datetime.datetime.utcnow()
    for ep in result.endpoints:
        db.add(WorldMonitorAPIEndpoint(
            target_id=target.id,
            method=safe_json(str(ep.method)),
            path=safe_json(ep.path),
            operation_id=safe_json(ep.operation_id),
            tags=ep.tags or [],
            source=safe_json(ep.source),
            authentication_hint=safe_json(ep.authentication_hint),
            first_seen=now,
            last_seen=now,
        ))
    db.commit()
    db.refresh(target)
    return _target_dict(target, db, include_inventory=True)


@router.get("/targets/{target_id}/inventory")
def target_inventory(target_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """The discovered, observable API inventory for one owned target."""
    target = _owned_target(db, user, target_id)
    rows = (
        db.query(WorldMonitorAPIEndpoint)
        .filter(WorldMonitorAPIEndpoint.target_id == target.id)
        .order_by(WorldMonitorAPIEndpoint.method.asc(), WorldMonitorAPIEndpoint.path.asc())
        .all()
    )
    return {
        "target_id": target.id,
        "status": target.status,
        "discovered_version": target.discovered_version,
        "endpoints": [_endpoint_dict(r) for r in rows],
    }


def safe_json(value):
    """Coerce arbitrary observed values into strings without losing data."""
    if value is None:
        return None
    return str(value)