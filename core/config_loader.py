"""
Soteria — Configuration Loader

Reads objectives.yaml and target_config.yaml, validates them against
Pydantic models, and returns typed configuration objects.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from core.models import (
    AttackObjective,
    LLMConfig,
    Severity,
    TargetConfig,
    TokenBudgetConfig,
)

# Default config directory relative to project root.
_CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"


def load_objectives(path: Path | None = None) -> list[AttackObjective]:
    """Load and validate attack objectives from a YAML file.

    Args:
        path: Path to objectives.yaml. Defaults to config/objectives.yaml.

    Returns:
        List of validated AttackObjective instances.
    """
    path = path or (_CONFIG_DIR / "objectives.yaml")
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))

    objectives: list[AttackObjective] = []
    for entry in raw.get("objectives", []):
        objectives.append(AttackObjective(
            id=entry["id"],
            owasp_category=entry["owasp_category"],
            severity=Severity(entry["severity"]),
            title=entry["title"],
            goal=entry["goal"].strip(),
            baseline_probe=entry["baseline_probe"].strip(),
            success_indicator=entry["success_indicator"].strip(),
            canary_tokens=entry.get("canary_tokens", []),
            forbidden_tool_calls=entry.get("forbidden_tool_calls", []),
        ))
    return objectives


def load_target_config(path: Path | None = None) -> TargetConfig:
    """Load and validate target configuration from a YAML file.

    Args:
        path: Path to target_config.yaml. Defaults to config/target_config.yaml.

    Returns:
        Validated TargetConfig instance.
    """
    path = path or (_CONFIG_DIR / "target_config.yaml")
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))

    target_section = raw["target"]
    attacker_section = raw["attacker"]
    judge_section = raw["judge"]
    orch_section = raw.get("orchestrator", {})
    report_section = raw.get("reports", {})

    return TargetConfig(
        target=LLMConfig(
            model=target_section["model"],
            temperature=target_section.get("temperature", 0.7),
            max_tokens=target_section.get("max_tokens", 1024),
        ),
        attacker=LLMConfig(
            model=attacker_section["model"],
            temperature=attacker_section.get("temperature", 0.95),
            max_tokens=attacker_section.get("max_tokens", 1024),
        ),
        judge=LLMConfig(
            model=judge_section["model"],
            temperature=judge_section.get("temperature", 0.1),
            max_tokens=judge_section.get("max_tokens", 512),
        ),
        system_prompt=target_section.get("system_prompt", "").strip(),
        canary_tokens=target_section.get("canary_tokens", []),
        forbidden_tool_calls=target_section.get("forbidden_tool_calls", []),
        max_turns=orch_section.get("max_turns", 5),
        concurrency=orch_section.get("concurrency", 3),
        token_budget=TokenBudgetConfig(
            max_total_tokens=orch_section.get("token_budget", {}).get("max_total_tokens", 50_000),
            max_cost_usd=orch_section.get("token_budget", {}).get("max_cost_usd", 0.05),
        ),
        auto_remediate=orch_section.get("auto_remediate", True),
        database_path=orch_section.get("database_path", "soteria_results.db"),
        asr_fail_threshold=report_section.get("asr_fail_threshold", 10.0),
    )
