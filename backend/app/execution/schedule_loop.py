"""Phase 12 continuous-assessment scheduler loop (in-process, opt-out).

The loop owns *recurrence only*: every due ``ScanSchedule`` execution creates a
brand-new ``Scan`` row (``source_schedule_id`` set) and enqueues it through the
normal background-scan path, so scheduled runs share the exact lifecycle,
attempt ledger and SSE contract of manual scans.  The loop never fabricates a
run: it ticks ``next_run_at`` deterministically, skips a schedule whose
previous run is still live, and never claims a run it did not enqueue.
"""
from __future__ import annotations

import datetime
import logging
import threading
import time

from app.workers.tasks import trigger_background_scan

logger = logging.getLogger("cyberagent.scheduler")

CADENCES = ("hourly", "daily", "weekly")


def _utcnow() -> datetime.datetime:
    return datetime.datetime.utcnow()


def next_run_at(cadence: str, interval: int, after: datetime.datetime | None = None) -> datetime.datetime:
    """Deterministic next execution time from cadence + interval."""
    base = after or _utcnow()
    cadence = (cadence or "daily").lower()
    step = max(int(interval or 1), 1)
    if cadence == "hourly":
        return base + datetime.timedelta(hours=step)
    if cadence == "weekly":
        return base + datetime.timedelta(weeks=step)
    return base + datetime.timedelta(days=step)


def _terminal_states():
    from app.agents import lifecycle
    return frozenset(lifecycle.TERMINAL_STAGES)


def _last_scan_still_live(db, schedule) -> bool:
    """True when this schedule's most recent scan has not reached a terminal
    state -- the schedule is skipped to avoid piling up overlapping runs."""
    last_id = schedule.last_scan_id
    if last_id is None:
        return False
    from database.models import Scan
    scan = db.query(Scan).filter(Scan.id == last_id).first()
    if scan is None:
        return False
    return (scan.stage or "") not in _terminal_states()


def _enqueue_from_schedule(db, schedule) -> int | None:
    """Create + enqueue one scheduled scan row (returns new scan id)."""
    from app.config import settings
    from app.core.auth import is_target_in_scope
    from app.agents import lifecycle
    from database.models import Asset, Scan, ScanAttempt

    project = schedule.project
    if project is None:
        logger.warning("Schedule %s has no project; skipping.", schedule.id)
        return None
    assets = db.query(Asset).filter(Asset.project_id == schedule.project_id).all()
    if not is_target_in_scope(schedule.target, project, assets):
        logger.warning("Schedule %s target out of scope; skipping run.", schedule.id)
        schedule.last_run_status = "failed"
        schedule.updated_at = _utcnow()
        return None

    config = dict(schedule.config or {})
    now = _utcnow()
    scan = Scan(
        project_id=schedule.project_id,
        target=schedule.target,
        status="Pending",
        stage=lifecycle.QUEUED,
        scan_config=config,
        assessment_type="custom_target",
        authorization_acknowledged=True,
        authorization_acknowledged_at=now,
        schedule_cadence=schedule.cadence,
        source_schedule_id=schedule.id,
        logs="[Scheduler] Scheduled run enqueued.\n",
    )
    db.add(scan)
    db.flush()
    scan.state = "created"
    db.add(ScanAttempt(scan_id=scan.id, attempt_number=1, trigger="schedule",
                       status="queued", created_at=now))
    # Seed the visible plan exactly like an interactive scan enqueue.
    from app.agents.workflow import _seed_progress
    config["simulation"] = settings.simulation_mode
    _seed_progress(db, scan, config, settings.simulation_mode)
    scan.queue_started_at = now
    db.commit()
    db.refresh(scan)

    try:
        trigger_background_scan(scan.id, simulation=settings.simulation_mode,
                                config=config)
    except Exception as exc:  # pragma: no cover - defensive
        logger.error("Schedule %s failed to enqueue scan %s: %s",
                     schedule.id, scan.id, exc)
        scan.stage = lifecycle.FAILED
        scan.status = "Failed"
        db.commit()
        return None
    return scan.id


def scheduler_tick(db) -> int:
    """Run every due enabled schedule; returns how many scans were enqueued."""
    from database.models import ScanSchedule

    due = (
        db.query(ScanSchedule)
        .filter(ScanSchedule.enabled.is_(True),
                ScanSchedule.next_run_at <= _utcnow())
        .all()
    )
    enqueued = 0
    now = _utcnow()
    for schedule in due:
        if _last_scan_still_live(db, schedule):
            continue
        try:
            scan_id = _enqueue_from_schedule(db, schedule)
        except Exception as exc:  # never let one bad schedule kill the loop
            logger.error("Schedule %s tick failed: %s", schedule.id, exc)
            db.rollback()
            continue
        schedule.last_run_at = now
        if scan_id is not None:
            schedule.last_run_status = "queued"
            schedule.last_scan_id = scan_id
        schedule.next_run_at = next_run_at(schedule.cadence, schedule.interval, after=now)
        schedule.updated_at = now
        db.commit()
        if scan_id is not None:
            enqueued += 1
    return enqueued


def run_scheduler_loop(stop_event: threading.Event,
                       tick_seconds: int = 60) -> None:
    """Blocking loop; owned exclusively by the scheduler daemon thread."""
    from database.connection import SessionLocal

    logger.info("Scheduler loop started (tick=%ss).", tick_seconds)
    while not stop_event.is_set():
        try:
            db = SessionLocal()
            try:
                scheduler_tick(db)
            finally:
                db.close()
        except Exception as exc:  # pragma: no cover - never kill the loop
            logger.error("Scheduler tick error: %s", exc)
        stop_event.wait(tick_seconds)
    logger.info("Scheduler loop stopped.")


def start_scheduler() -> threading.Event:
    """Start the scheduler daemon thread; returns its stop event."""
    from app.config import settings

    stop_event = threading.Event()
    if not settings.scheduler_enabled:
        return stop_event
    thread = threading.Thread(
        target=run_scheduler_loop,
        args=(stop_event, settings.scheduler_tick_seconds),
        name="cyberagent-scheduler",
        daemon=True,
    )
    thread.start()
    logger.info("Scheduler thread started (enabled=%s).", settings.scheduler_enabled)
    return stop_event


__all__ = ["scheduler_tick", "next_run_at", "run_scheduler_loop", "start_scheduler"]