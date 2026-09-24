"""Phase 12 schedules API: operator-defined recurrent scans.

A schedule is a recurrence definition.  Creating it requires the same scope
authorization as an interactive scan; when it is due, the scheduler enqueues a
fresh scan through the normal path (never fabricating an execution).
"""
from __future__ import annotations

import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.auth import (
    is_target_in_scope,
    get_current_user,
    get_or_create_user_project,
)
from database.connection import get_db
from database.models import Asset, Project, Scan, ScanSchedule, User
from app.execution.schedule_loop import CADENCES, next_run_at

router = APIRouter(prefix="/schedules", tags=["schedules"])


class ScheduleCreate(BaseModel):
    target: str
    cadence: str = Field(default="daily", pattern="^(hourly|daily|weekly)$")
    interval: int = Field(default=1, ge=1, le=90)
    name: str | None = None
    enabled: bool = True
    config: dict | None = None


class ScheduleUpdate(BaseModel):
    enabled: bool | None = None
    cadence: str | None = Field(default=None, pattern="^(hourly|daily|weekly)$")
    interval: int | None = Field(default=None, ge=1, le=90)
    name: str | None = None


def _schedule_dict(db, s: ScanSchedule) -> dict:
    last_scan = db.query(Scan).filter(Scan.id == s.last_scan_id).first() if s.last_scan_id else None
    return {
        "id": s.id,
        "name": s.name,
        "target": s.target,
        "cadence": s.cadence,
        "interval": s.interval,
        "enabled": bool(s.enabled),
        "next_run_at": s.next_run_at.isoformat() if s.next_run_at else None,
        "last_run_at": s.last_run_at.isoformat() if s.last_run_at else None,
        "last_run_status": s.last_run_status,
        "last_scan_id": s.last_scan_id,
        "last_scan_state": last_scan.stage if last_scan else None,
        "created_at": s.created_at.isoformat() if s.created_at else None,
    }


@router.get("")
def list_schedules(user: User = Depends(get_current_user),
                   db: Session = Depends(get_db)):
    projects = db.query(Project).filter(Project.user_id == user.id).all()
    ids = [p.id for p in projects]
    if not ids:
        return []
    rows = (
        db.query(ScanSchedule)
        .filter(ScanSchedule.project_id.in_(ids))
        .order_by(ScanSchedule.id.asc())
        .all()
    )
    return [_schedule_dict(db, s) for s in rows]


@router.post("")
def create_schedule(payload: ScheduleCreate,
                    user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)):
    """Create a new recurrent scan definition (scope-checked like a scan)."""
    project = get_or_create_user_project(db, user)
    assets = db.query(Asset).filter(Asset.project_id == project.id).all()
    if not is_target_in_scope(payload.target, project, assets):
        raise HTTPException(
            status_code=403,
            detail="Target is outside the authorized scope for this project.",
        )
    row = ScanSchedule(
        user_id=user.id,
        project_id=project.id,
        name=payload.name,
        target=payload.target,
        cadence=payload.cadence,
        interval=payload.interval,
        enabled=bool(payload.enabled),
        next_run_at=next_run_at(payload.cadence, payload.interval),
        config=dict(payload.config or {}),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return _schedule_dict(db, row)


@router.patch("/{schedule_id}")
def update_schedule(schedule_id: int,
                    payload: ScheduleUpdate,
                    user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)):
    row = db.query(ScanSchedule).filter(ScanSchedule.id == schedule_id).first()
    if row is None or row.user_id != user.id:
        raise HTTPException(status_code=404, detail="Schedule not found.")
    if payload.enabled is not None:
        row.enabled = bool(payload.enabled)
    if payload.cadence is not None:
        row.cadence = payload.cadence
    if payload.interval is not None:
        row.interval = payload.interval
    if payload.name is not None:
        row.name = payload.name
    if row.cadence in CADENCES:
        row.next_run_at = next_run_at(row.cadence, row.interval)
    row.updated_at = datetime.datetime.utcnow()
    db.commit()
    db.refresh(row)
    return _schedule_dict(db, row)


@router.delete("/{schedule_id}")
def delete_schedule(schedule_id: int,
                    user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)):
    row = db.query(ScanSchedule).filter(ScanSchedule.id == schedule_id).first()
    if row is None or row.user_id != user.id:
        raise HTTPException(status_code=404, detail="Schedule not found.")
    row.enabled = False
    row.updated_at = datetime.datetime.utcnow()
    db.commit()
    return {"id": row.id, "deleted": True, "disabled": True}


@router.get("/{schedule_id}/scans")
def schedule_scans(schedule_id: int,
                   user: User = Depends(get_current_user),
                   db: Session = Depends(get_db)):
    row = db.query(ScanSchedule).filter(ScanSchedule.id == schedule_id).first()
    if row is None or row.user_id != user.id:
        raise HTTPException(status_code=404, detail="Schedule not found.")
    scans = (
        db.query(Scan)
        .filter(Scan.source_schedule_id == schedule_id)
        .order_by(Scan.created_at.desc())
        .all()
    )
    return [
        {
            "id": s.id,
            "target": s.target,
            "status": s.status,
            "stage": s.stage,
            "state": s.state,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
        }
        for s in scans
    ]


__all__ = ["router"]