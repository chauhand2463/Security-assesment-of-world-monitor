"""Phase 10.3 parallel execution scheduler.

The scan plan is a dependency-ordered sequence of stage barriers holding
independent tools (``stage:<NAME>`` marks a barrier; ``tool:<NAME>`` is a leaf
that only depends on the stages before it).  The scheduler preserves that DAG:

  * stages run in order (barriers: a stage never starts before its predecessor
    finished),
  * tools *within* one stage run concurrently, bounded by the operator's
    ``max_parallel_tools`` (a real bound, never unbounded fan-out),
  * each worker uses its own DB session (SQLAlchemy sessions are not
    thread-safe), reloads a fresh Scan row, executes, commits and closes,
  * per-scan cancellation is honored before stages and inside adapters via the
    shared ``job``; a cancelled job aborts the remaining plan,
  * a worker failure is isolated: it marks that one tool failed and never
    aborts the sibling tools, and it never fabricates success for a tool that
    did not run.

The honest record of how a plan was executed (strategy, bound, counts) is
persisted in a ``ScanExecution`` row by the pipeline driver.
"""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from app.orchestration import executions
from app.workers.tasks import ScanCancelled
from app.tools import scanner_tools

logger = logging.getLogger("cyberagent.scheduler")

DEFAULT_MAX_PARALLEL = 1
MAX_PARALLEL_LIMIT = 8


def max_parallel_tools(config: dict | None) -> int:
    """The bounded concurrency the operator requested (clamped 1..8, default 1).

    Sequential (1) is the safe default: the event trail and UI stream stay in
    id order, exactly as earlier phases defined them.  Operators opt into
    bounded parallelism per scan via ``max_parallel_tools`` once they need the
    wall-clock win; the bound is still clamped below 1 (sequential) so an
    unset or nonsense value never fans out work.
    """
    raw = (config or {}).get("max_parallel_tools", DEFAULT_MAX_PARALLEL)
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = DEFAULT_MAX_PARALLEL
    if value < 1:
        value = 1
    if value > MAX_PARALLEL_LIMIT:
        value = MAX_PARALLEL_LIMIT
    return value


def group_plan(config: dict | None) -> list[dict]:
    """Flatten ``plan_tasks`` into ordered stage groups with their tools.

    Mirrors ``plan_tasks`` exactly (same enabled-tool selection, same stage
    order) so the pubic plan and the executed plan can never diverge.
    """
    from app.orchestration.stages import plan_tasks

    groups: list[dict] = []
    current: dict | None = None
    for task in plan_tasks(config):
        if task.startswith("stage:"):
            current = {"stage": task.split(":", 1)[1], "tools": []}
            groups.append(current)
        elif task.startswith("tool:") and current is not None:
            current["tools"].append(task.split(":", 1)[1])
    return groups


def _worker_once(db, scan, tool: str, config: dict, job, state: dict, runner) -> dict:
    """Run one tool inside its own session; returns a result dict (never raises).

    Any outcome short of a completed success is an honest failure report:
    worker crashes become ``STATE_EXECUTION_FAILED`` (real, observed), never a
    fabricated success.
    """
    try:
        return runner(db, scan, tool, config, job, state)
    except ScanCancelled:
        raise
    except Exception as exc:  # isolation: one worker's crash never kills siblings
        logger.warning(f"[{tool}] worker crashed: {exc}")
        return {
            "tool": tool,
            "status": scanner_tools.STATE_EXECUTION_FAILED,
            "error": str(exc)[:500],
        }


def execute_batch(db, scan, config, job, state, tools, *, runner=None) -> list[dict]:
    """Run a stage's tools, bounded to ``max_parallel_tools``.

    Always returns one result dict per tool (in plan order).  ``runner`` is the
    per-tool callable (default ``executions.execute_tool``), kept injectable for
    tests.  Scans with concurrency 1 keep a strictly sequential, same-session
    execution path identical to the Phase 7 linear driver (exceptions propagate
    exactly as they did before; failures are only isolated between parallel
    workers).
    """
    runner = runner or executions.execute_tool
    if not tools:
        return []
    limit = max_parallel_tools(config)
    if limit <= 1 or len(tools) <= 1:
        return [runner(db, scan, tool, config, job, state) for tool in tools]

    from database.connection import SessionLocal
    from database.models import Scan

    scan_id = scan.id

    def _worker(tool: str) -> tuple[str, dict]:
        worker_db = SessionLocal()
        try:
            local_scan = worker_db.query(Scan).filter(Scan.id == scan_id).first()
            if local_scan is None:  # race with deletion; honest failure
                return tool, {"tool": tool,
                              "status": scanner_tools.STATE_EXECUTION_FAILED,
                              "error": "scan row vanished during execution"}
            result = _worker_once(worker_db, local_scan, tool, config, job, state, runner)
            worker_db.commit()
            return tool, result
        except ScanCancelled:
            worker_db.rollback()
            raise
        except Exception as exc:  # pragma: no cover - defensive
            worker_db.rollback()
            logger.warning(f"[{tool}] worker session failed: {exc}")
            return tool, {"tool": tool,
                          "status": scanner_tools.STATE_EXECUTION_FAILED,
                          "error": str(exc)[:500]}
        finally:
            worker_db.close()

    results: dict[str, dict] = {}
    pool = ThreadPoolExecutor(max_workers=min(limit, len(tools)),
                              thread_name_prefix="cyberagent-tool")
    futures = {pool.submit(_worker, tool): tool for tool in tools}
    cancelled = False
    try:
        for fut in as_completed(futures):
            tool = futures[fut]
            try:
                _, result = fut.result()
            except ScanCancelled:
                cancelled = True
                break
            results[tool] = result
    finally:
        pool.shutdown(wait=True, cancel_futures=True)
    if cancelled:
        raise ScanCancelled()
    return [results.get(tool, {"tool": tool,
                               "status": scanner_tools.STATE_EXECUTION_FAILED,
                               "error": "tool abandoned by cancellation"})
            for tool in tools]


__all__ = [
    "DEFAULT_MAX_PARALLEL", "MAX_PARALLEL_LIMIT",
    "max_parallel_tools", "group_plan", "execute_batch",
]