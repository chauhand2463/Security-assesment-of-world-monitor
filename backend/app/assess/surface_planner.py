"""Phase 12 surface assessment planner (program, not execution).

Builds an explicit, auditable assessment *program* from the observed surface:
for every registered security test it decides -- deterministically, from
persisted evidence only -- which observed endpoints/parameters the test would
apply to, or skips it with a concrete reason.  The engine planner remains the
authority on final applicability during a real run; this module surfaces the
intent *before* execution so operators can see the plan, not a black box.

Nothing runs here: it reads persisted observations and returns a plan.
"""
from __future__ import annotations

import datetime
from dataclasses import dataclass, field

from app.assess.registry import default_registry
from app.discovery.inventory import endpoint_inventory, parameter_inventory

# Tests whose verdict is per-endpoint surface metadata (passive checks).
ENDPOINT_SCOPED_CATEGORIES = {
    "headers", "cors", "cookies", "methods", "redirects", "tls", "disclosure",
}
# Tests whose verdict is per-observed-parameter (they need real parameters).
PARAMETER_SCOPED_CATEGORIES = {
    "xss", "sqli", "ssti", "ssrf", "idor", "authorization", "auth", "jwt",
    "oauth", "graphql",
}


@dataclass
class SurfaceTask:
    test_id: str
    name: str
    category: str
    active: bool
    status: str  # "planned" | "skipped"
    reason: str
    endpoints: list[str] = field(default_factory=list)
    parameters: list[str] = field(default_factory=list)


@dataclass
class SurfacePlan:
    scan_id: int
    target: str
    generated_at: str
    tests_total: int
    tests_planned: int = 0
    tests_skipped: int = 0
    tasks: list[SurfaceTask] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "generated_at": self.generated_at,
            "tests_total": self.tests_total,
            "tests_planned": self.tests_planned,
            "tests_skipped": self.tests_skipped,
            "tasks": [
                {
                    "test_id": t.test_id,
                    "name": t.name,
                    "category": t.category,
                    "active": bool(t.active),
                    "status": t.status,
                    "reason": t.reason,
                    "endpoints": list(t.endpoints),
                    "parameters": list(t.parameters),
                }
                for t in self.tasks
            ],
        }


def plan_surface(db, scan) -> SurfacePlan:
    """Deterministic assessment program derived from the observed surface."""
    registry = default_registry()
    endpoints = endpoint_inventory(db, scan.id)
    params = parameter_inventory(db, scan.id)

    params_by_endpoint: dict[str, list[str]] = {}
    for item in params:
        params_by_endpoint.setdefault(item["endpoint"], [])
        if item["parameter"] not in params_by_endpoint[item["endpoint"]]:
            params_by_endpoint[item["endpoint"]].append(item["parameter"])

    plan = SurfacePlan(
        scan_id=scan.id,
        target=scan.target,
        generated_at=datetime.datetime.utcnow().isoformat(),
        tests_total=0,
    )

    for test in registry.all():
        plan.tests_total += 1
        category = test.category or ""
        active = bool(getattr(test, "active", False))

        if category in ENDPOINT_SCOPED_CATEGORIES:
            targets = list(endpoints)
            scope_label = "endpoint"
        elif category in PARAMETER_SCOPED_CATEGORIES:
            targets = [e for e in endpoints if e["url"] in params_by_endpoint]
            scope_label = "parameterised endpoint"
        else:
            plan.tasks.append(SurfaceTask(
                test_id=test.id, name=test.name, category=category, active=active,
                status="skipped", reason="test category is not surface-scoped",
            ))
            plan.tests_skipped += 1
            continue

        if not targets:
            plan.tasks.append(SurfaceTask(
                test_id=test.id, name=test.name, category=category, active=active,
                status="skipped",
                reason=f"no observed {scope_label}(s) on this surface; nothing to plan",
            ))
            plan.tests_skipped += 1
            continue

        url_list = [e["url"] for e in targets]
        param_list: list[str] = []
        for e in targets:
            for name in params_by_endpoint.get(e["url"], []):
                if name not in param_list:
                    param_list.append(name)
        plan.tasks.append(SurfaceTask(
            test_id=test.id, name=test.name, category=category, active=active,
            status="planned",
            reason=(f"planned against {len(url_list)} observed {scope_label}(s) "
                    f"({len(param_list)} observed parameter(s) in scope)"),
            endpoints=url_list,
            parameters=param_list,
        ))
        plan.tests_planned += 1

    return plan


__all__ = ["plan_surface", "SurfacePlan", "ENDPOINT_SCOPED_CATEGORIES",
           "PARAMETER_SCOPED_CATEGORIES"]