"""
Soteria — Pytest Plugin

Integrates Soteria's red-team harness into standard pytest workflows.
Developers can run security regression checks with:

    pytest --redteam
    pytest --redteam --redteam-filter LLM01
    pytest --redteam --redteam-max-turns 3

The plugin registers as a pytest11 entry point (see pyproject.toml),
so it auto-discovers when Soteria is installed.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest


def pytest_addoption(parser):
    """Register Soteria-specific CLI options with pytest."""
    group = parser.getgroup("soteria", "Soteria Red-Team Options")
    group.addoption(
        "--redteam",
        action="store_true",
        default=False,
        help="Enable Soteria adversarial red-team tests.",
    )
    group.addoption(
        "--redteam-config",
        type=str,
        default=None,
        help="Path to target_config.yaml.",
    )
    group.addoption(
        "--redteam-objectives",
        type=str,
        default=None,
        help="Path to objectives.yaml.",
    )
    group.addoption(
        "--redteam-filter",
        type=str,
        action="append",
        default=None,
        help="Only run objectives matching this ID prefix (repeatable).",
    )
    group.addoption(
        "--redteam-max-turns",
        type=int,
        default=None,
        help="Override max iterations per objective.",
    )
    group.addoption(
        "--redteam-asr-threshold",
        type=float,
        default=None,
        help="Override ASR failure threshold (percent).",
    )


def pytest_configure(config):
    """Register the 'redteam' marker."""
    config.addinivalue_line(
        "markers",
        "redteam: marks tests as Soteria red-team security tests.",
    )


def pytest_collection_modifyitems(config, items):
    """Skip red-team tests unless --redteam is passed."""
    if not config.getoption("--redteam"):
        skip_marker = pytest.mark.skip(reason="Red-team tests require --redteam flag.")
        for item in items:
            if "redteam" in item.keywords:
                item.add_marker(skip_marker)


@pytest.fixture(scope="session")
def soteria_config(request):
    """Session-scoped fixture that loads and returns TargetConfig."""
    from core.config_loader import load_target_config

    config_path = request.config.getoption("--redteam-config")
    config = load_target_config(
        Path(config_path) if config_path else None
    )

    # Apply CLI overrides.
    max_turns = request.config.getoption("--redteam-max-turns")
    if max_turns is not None:
        config.max_turns = max_turns

    threshold = request.config.getoption("--redteam-asr-threshold")
    if threshold is not None:
        config.asr_fail_threshold = threshold

    return config


@pytest.fixture(scope="session")
def soteria_objectives(request):
    """Session-scoped fixture that loads attack objectives."""
    from core.config_loader import load_objectives

    obj_path = request.config.getoption("--redteam-objectives")
    objectives = load_objectives(
        Path(obj_path) if obj_path else None
    )

    # Apply filter if specified.
    filters = request.config.getoption("--redteam-filter")
    if filters:
        objectives = [
            obj for obj in objectives
            if any(obj.id.startswith(f) for f in filters)
        ]

    return objectives


@pytest.fixture(scope="session")
def soteria_audit(soteria_config, soteria_objectives):
    """Session-scoped fixture that runs the full audit and returns the report.

    This executes the entire red-team loop once per test session,
    making results available to all red-team test functions.
    """
    from core.orchestrator import run_audit

    report = asyncio.run(
        run_audit(soteria_config, soteria_objectives)
    )
    return report


# ╭──────────────────────────────────────────────────────────────╮
# │  Built-in Test Functions                                     │
# ╰──────────────────────────────────────────────────────────────╯

@pytest.mark.redteam
def test_asr_below_threshold(soteria_audit, soteria_config):
    """Assert that the Attack Success Rate stays below the CI/CD threshold.

    This is the primary CI/CD gate test — if ASR exceeds the configured
    threshold, the build fails.
    """
    assert soteria_audit.ci_gate_passed, (
        f"SECURITY REGRESSION: Attack Success Rate is "
        f"{soteria_audit.asr_percent:.1f}% "
        f"(threshold: {soteria_config.asr_fail_threshold}%). "
        f"Breached objectives: {soteria_audit.breached_objectives}"
        f"/{soteria_audit.total_objectives}."
    )


@pytest.mark.redteam
def test_no_critical_breaches(soteria_audit):
    """Assert that no CRITICAL-severity objectives were breached.

    Even if overall ASR is low, a breach on a critical objective
    should always fail the build.
    """
    critical_breaches = [
        run for run in soteria_audit.runs
        if run.breach_achieved and run.objective.severity.value == "critical"
    ]
    assert len(critical_breaches) == 0, (
        f"CRITICAL BREACH detected in: "
        f"{[r.objective.id for r in critical_breaches]}. "
        f"These must be fixed before merging."
    )


@pytest.mark.redteam
def test_token_budget_respected(soteria_audit, soteria_config):
    """Assert that the audit stayed within the configured token budget."""
    assert soteria_audit.total_tokens <= soteria_config.token_budget.max_total_tokens, (
        f"Token budget exceeded: {soteria_audit.total_tokens:,} tokens used "
        f"(limit: {soteria_config.token_budget.max_total_tokens:,})."
    )
