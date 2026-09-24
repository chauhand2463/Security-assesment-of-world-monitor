"""Phase 7 pipeline stage catalogue unit tests.

The 13-stage plan must be ordered, map every tool to exactly one stage, keep
the legacy ``Scan.stage`` vocabulary, and make pentest extras strictly opt-in.
"""

from app.orchestration import stages


def test_stage_order_is_13_well_formed():
    assert len(stages.STAGE_ORDER) == 13
    assert stages.STAGE_ORDER[0] == stages.PRECHECK
    assert stages.STAGE_ORDER[-1] == stages.REPORTING
    assert len(set(stages.STAGE_ORDER)) == 13


def test_every_stage_has_a_legacy_stage_and_it_is_known():
    from app.agents import lifecycle
    legacy_values = {
        lifecycle.QUEUED, lifecycle.STARTING, lifecycle.RECON, lifecycle.DISCOVERY,
        lifecycle.SERVICE_SCAN, lifecycle.HTTP_SCAN, lifecycle.VULNERABILITY_SCAN,
        lifecycle.ANALYSIS, lifecycle.REPORTING,
    }
    for stage in stages.STAGE_ORDER:
        assert stages.LEGACY_STAGE[stage] in legacy_values, stage


def test_tools_map_to_existing_stages():
    assert set(stages.TOOL_TO_STAGE.values()) <= set(stages.STAGE_ORDER)
    for tool, stage in stages.TOOL_TO_STAGE.items():
        assert tool in stages.STAGE_TOOLS[stage]


def test_default_tools_cover_the_builtin_plan_and_extras_are_opt_in():
    builtin = {"real_dns", "real_tcp", "real_http", "world_monitor_discovery",
               "endpoint_discovery",
               "subfinder", "assetfinder",
               "dnsx", "nmap", "httpx", "gau", "whatweb", "nuclei"}
    assert set(stages.TOOL_TO_STAGE) == builtin | set(stages._PENTEST_EXTRAS)
    for tool in builtin:
        assert stages.DEFAULT_TOOLS[tool] is True
    for tool in stages._PENTEST_EXTRAS:
        assert stages.DEFAULT_TOOLS[tool] is False


def test_enabled_semantics_extras_are_opt_in():
    assert stages.enabled({"tools": {"ffuf": False}}, "ffuf") is False
    assert stages.enabled({}, "ffuf") is False  # never on silently
    assert stages.enabled({"tools": {"ffuf": True}}, "ffuf") is True
    assert stages.enabled({}, "nmap") is True
    assert stages.enabled({"tools": {"nmap": False}}, "nmap") is False
    assert stages.is_extra("ffuf") and not stages.is_extra("nmap")


def test_plan_tasks_is_interleaved_and_ordered():
    tasks = stages.plan_tasks({})
    assert tasks[0] == "stage:PRECHECK"
    assert tasks[-1] == "stage:REPORTING"
    stage_names = [t.split(":", 1)[1] for t in tasks if t.startswith("stage:")]
    assert stage_names == list(stages.STAGE_ORDER)

    current_stage = None
    for t in tasks:
        if t.startswith("stage:"):
            current_stage = t.split(":", 1)[1]
            continue
        assert current_stage is not None
        tool = t.split(":", 1)[1]
        assert tool in stages.STAGE_TOOLS[current_stage]
        assert stages.TOOL_TO_STAGE[tool] == current_stage

    tool_tasks = [t for t in tasks if t.startswith("tool:")]
    assert len(tool_tasks) == stages.plan_tool_count({})
    assert tool_tasks[0] == "tool:real_dns"  # target normalization first


def test_disabled_tools_are_left_out_of_the_plan():
    tasks = stages.plan_tasks({"tools": {"subfinder": False, "nuclei": False}})
    tools = {t.split(":", 1)[1] for t in tasks if t.startswith("tool:")}
    assert "subfinder" not in tools
    assert "nuclei" not in tools
    assert "nmap" in tools


def test_extras_only_in_plan_when_opt_in():
    plain = {t.split(":", 1)[1] for t in stages.plan_tasks({}) if t.startswith("tool:")}
    for extra in stages._PENTEST_EXTRAS:
        assert extra not in plain
    with_extra = stages.plan_tasks({"tools": {"ffuf": True}})
    fwd = {t.split(":", 1)[1] for t in with_extra if t.startswith("tool:")}
    assert "ffuf" in fwd
    assert "sqlmap" not in fwd


def test_plan_tool_count():
    assert stages.plan_tool_count({}) == len(
        [t for t in stages.plan_tasks({}) if t.startswith("tool:")])
    assert stages.plan_tool_count({"tools": {"nmap": False}}) == \
        stages.plan_tool_count({}) - 1