"""
Soteria — SQLite Database Logger (Async)

Stores every prompt/response mutation tree in a single local .db file
using aiosqlite for non-blocking writes. Supports querying for the
Streamlit dashboard and HTML report generation.
"""

from __future__ import annotations

import json
from pathlib import Path

import aiosqlite

from core.models import AttackRunResult, AuditReport, IterationResult

# ── Schema ───────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_runs (
    audit_id       TEXT PRIMARY KEY,
    started_at     TEXT NOT NULL,
    finished_at    TEXT,
    total_objectives   INTEGER DEFAULT 0,
    breached_objectives INTEGER DEFAULT 0,
    asr_percent    REAL DEFAULT 0.0,
    total_tokens   INTEGER DEFAULT 0,
    total_cost_usd REAL DEFAULT 0.0,
    ci_gate_passed INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS attack_runs (
    run_id         TEXT PRIMARY KEY,
    audit_id       TEXT NOT NULL,
    objective_id   TEXT NOT NULL,
    objective_json TEXT NOT NULL,
    best_score     INTEGER DEFAULT 0,
    breach_achieved INTEGER DEFAULT 0,
    breach_iteration INTEGER,
    remediation_json TEXT,
    total_tokens   INTEGER DEFAULT 0,
    total_cost_usd REAL DEFAULT 0.0,
    started_at     TEXT NOT NULL,
    finished_at    TEXT,
    FOREIGN KEY (audit_id) REFERENCES audit_runs(audit_id)
);

CREATE TABLE IF NOT EXISTS iterations (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id           TEXT NOT NULL,
    iteration        INTEGER NOT NULL,
    mutator_type     TEXT,
    attack_prompt    TEXT NOT NULL,
    target_response  TEXT NOT NULL,
    target_latency_ms REAL DEFAULT 0.0,
    judge_verdict_json TEXT,
    deterministic_flags_json TEXT,
    token_usage_json TEXT,
    timestamp        TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES attack_runs(run_id)
);

CREATE INDEX IF NOT EXISTS idx_iterations_run ON iterations(run_id);
CREATE INDEX IF NOT EXISTS idx_attack_runs_audit ON attack_runs(audit_id);
"""


class DatabaseLogger:
    """Async SQLite logger for attack trees and token usage.

    Usage:
        async with DatabaseLogger("soteria_results.db") as db:
            await db.save_audit(report)
            runs = await db.get_audit_runs("abc123")
    """

    def __init__(self, db_path: str | Path = "soteria_results.db"):
        self._db_path = str(db_path)
        self._conn: aiosqlite.Connection | None = None

    async def __aenter__(self) -> DatabaseLogger:
        self._conn = await aiosqlite.connect(self._db_path)
        await self._conn.executescript(_SCHEMA)
        await self._conn.commit()
        return self

    async def __aexit__(self, *exc) -> None:
        if self._conn:
            await self._conn.close()
            self._conn = None

    async def _ensure_connected(self) -> aiosqlite.Connection:
        if self._conn is None:
            self._conn = await aiosqlite.connect(self._db_path)
            await self._conn.executescript(_SCHEMA)
            await self._conn.commit()
        return self._conn

    # ── Write Operations ─────────────────────────────────────────────

    async def save_iteration(self, run_id: str, it: IterationResult) -> None:
        """Persist a single attack iteration."""
        conn = await self._ensure_connected()
        await conn.execute(
            """INSERT INTO iterations
               (run_id, iteration, mutator_type, attack_prompt, target_response,
                target_latency_ms, judge_verdict_json, deterministic_flags_json,
                token_usage_json, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id,
                it.iteration,
                it.mutator_type.value,
                it.attack_prompt,
                it.target_response,
                it.target_latency_ms,
                it.judge_verdict.model_dump_json() if it.judge_verdict else None,
                json.dumps(it.deterministic_flags),
                it.token_usage.model_dump_json(),
                it.timestamp.isoformat(),
            ),
        )
        await conn.commit()

    async def save_attack_run(self, audit_id: str, run: AttackRunResult) -> None:
        """Persist a complete attack run (all iterations for one objective)."""
        conn = await self._ensure_connected()
        await conn.execute(
            """INSERT OR REPLACE INTO attack_runs
               (run_id, audit_id, objective_id, objective_json, best_score,
                breach_achieved, breach_iteration, remediation_json,
                total_tokens, total_cost_usd, started_at, finished_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                run.run_id,
                audit_id,
                run.objective.id,
                run.objective.model_dump_json(),
                run.best_score,
                int(run.breach_achieved),
                run.breach_iteration,
                run.remediation.model_dump_json() if run.remediation else None,
                run.total_tokens,
                run.total_cost_usd,
                run.started_at.isoformat(),
                run.finished_at.isoformat() if run.finished_at else None,
            ),
        )
        # Also save each iteration.
        for it in run.iterations:
            await self.save_iteration(run.run_id, it)

    async def save_audit(self, report: AuditReport) -> None:
        """Persist a full audit report with all attack runs."""
        conn = await self._ensure_connected()
        await conn.execute(
            """INSERT OR REPLACE INTO audit_runs
               (audit_id, started_at, finished_at, total_objectives,
                breached_objectives, asr_percent, total_tokens,
                total_cost_usd, ci_gate_passed)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                report.audit_id,
                report.started_at.isoformat(),
                report.finished_at.isoformat() if report.finished_at else None,
                report.total_objectives,
                report.breached_objectives,
                report.asr_percent,
                report.total_tokens,
                report.total_cost_usd,
                int(report.ci_gate_passed),
            ),
        )
        for run in report.runs:
            await self.save_attack_run(report.audit_id, run)
        await conn.commit()

    # ── Read Operations ──────────────────────────────────────────────

    async def get_all_audits(self) -> list[dict]:
        """Return all audit run summaries, newest first."""
        conn = await self._ensure_connected()
        cursor = await conn.execute(
            "SELECT * FROM audit_runs ORDER BY started_at DESC"
        )
        columns = [desc[0] for desc in cursor.description]
        rows = await cursor.fetchall()
        return [dict(zip(columns, row)) for row in rows]

    async def get_attack_runs(self, audit_id: str) -> list[dict]:
        """Return all attack runs for a given audit."""
        conn = await self._ensure_connected()
        cursor = await conn.execute(
            "SELECT * FROM attack_runs WHERE audit_id = ? ORDER BY started_at",
            (audit_id,),
        )
        columns = [desc[0] for desc in cursor.description]
        rows = await cursor.fetchall()
        return [dict(zip(columns, row)) for row in rows]

    async def get_iterations(self, run_id: str) -> list[dict]:
        """Return all iterations for a given attack run."""
        conn = await self._ensure_connected()
        cursor = await conn.execute(
            "SELECT * FROM iterations WHERE run_id = ? ORDER BY iteration",
            (run_id,),
        )
        columns = [desc[0] for desc in cursor.description]
        rows = await cursor.fetchall()
        return [dict(zip(columns, row)) for row in rows]

    async def get_category_stats(self, audit_id: str) -> list[dict]:
        """Return breach stats grouped by OWASP category for an audit."""
        conn = await self._ensure_connected()
        cursor = await conn.execute(
            """SELECT
                 json_extract(objective_json, '$.owasp_category') as category,
                 COUNT(*) as total,
                 SUM(breach_achieved) as breached,
                 ROUND(AVG(best_score), 1) as avg_score
               FROM attack_runs
               WHERE audit_id = ?
               GROUP BY category
               ORDER BY breached DESC""",
            (audit_id,),
        )
        columns = [desc[0] for desc in cursor.description]
        rows = await cursor.fetchall()
        return [dict(zip(columns, row)) for row in rows]
