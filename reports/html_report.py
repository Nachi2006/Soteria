"""
Soteria — HTML Report Generator

Generates a standalone HTML vulnerability scorecard with embedded CSS.
No external dependencies — the report is a single self-contained file
that can be opened in any browser or attached to a CI/CD artifact.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path

from core.models import AuditReport, AttackRunResult


def _severity_color(severity: str) -> str:
    """Return a CSS color for a severity level."""
    return {
        "critical": "#e74c3c",
        "high": "#e67e22",
        "medium": "#f1c40f",
        "low": "#2ecc71",
        "info": "#3498db",
    }.get(severity.lower(), "#95a5a6")


def _score_color(score: int) -> str:
    """Return a CSS color for a judge score."""
    return {
        1: "#2ecc71", 2: "#a8d855", 3: "#f1c40f",
        4: "#e67e22", 5: "#e74c3c",
    }.get(score, "#95a5a6")


def _score_label(score: int) -> str:
    """Return a human label for a judge score."""
    return {
        1: "Safe Refusal", 2: "Partial Refusal", 3: "Hedged Leakage",
        4: "Significant Breach", 5: "Full Breach",
    }.get(score, "Unknown")


def generate_html_report(report: AuditReport, output_path: Path) -> Path:
    """Generate a self-contained HTML report from an AuditReport.

    Args:
        report: The completed audit report.
        output_path: Directory to write the HTML file.

    Returns:
        Path to the generated HTML file.
    """
    output_path.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filepath = output_path / f"soteria_report_{timestamp}.html"

    gate_class = "pass" if report.ci_gate_passed else "fail"
    gate_text = "PASSED" if report.ci_gate_passed else "FAILED"

    # Build per-objective rows.
    objective_rows = []
    for run in report.runs:
        objective_rows.append(_build_run_section(run))

    # Build category stats.
    category_stats = _build_category_stats(report)

    html_content = f"""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Soteria — Red-Team Audit Report</title>
<style>
:root {{
    --bg: #0f1117; --surface: #1a1d27; --surface2: #252830;
    --text: #e4e6eb; --text2: #9ca3af; --accent: #6366f1;
    --red: #e74c3c; --green: #2ecc71; --yellow: #f1c40f; --orange: #e67e22;
    --blue: #3498db; --border: #2d3039;
}}
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family:'Segoe UI',system-ui,sans-serif; background:var(--bg); color:var(--text); line-height:1.6; padding:2rem; }}
.container {{ max-width:1200px; margin:0 auto; }}
h1 {{ font-size:2rem; background:linear-gradient(135deg,var(--accent),#a855f7); -webkit-background-clip:text; -webkit-text-fill-color:transparent; margin-bottom:0.5rem; }}
h2 {{ color:var(--accent); margin:2rem 0 1rem; font-size:1.3rem; border-bottom:1px solid var(--border); padding-bottom:0.5rem; }}
h3 {{ color:var(--text); font-size:1.1rem; margin:1rem 0 0.5rem; }}
.subtitle {{ color:var(--text2); font-size:0.9rem; margin-bottom:2rem; }}
.metrics {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:1rem; margin:1.5rem 0; }}
.metric {{ background:var(--surface); border:1px solid var(--border); border-radius:12px; padding:1.2rem; text-align:center; }}
.metric .value {{ font-size:1.8rem; font-weight:700; }}
.metric .label {{ font-size:0.8rem; color:var(--text2); text-transform:uppercase; letter-spacing:0.05em; }}
.gate {{ border-radius:12px; padding:1rem 1.5rem; font-size:1.1rem; font-weight:700; text-align:center; margin:1.5rem 0; }}
.gate.pass {{ background:rgba(46,204,113,0.15); border:2px solid var(--green); color:var(--green); }}
.gate.fail {{ background:rgba(231,76,60,0.15); border:2px solid var(--red); color:var(--red); }}
table {{ width:100%; border-collapse:collapse; margin:1rem 0; }}
th {{ background:var(--surface2); color:var(--text2); text-transform:uppercase; font-size:0.75rem; letter-spacing:0.05em; padding:0.8rem; text-align:left; }}
td {{ padding:0.7rem 0.8rem; border-bottom:1px solid var(--border); font-size:0.9rem; }}
tr:hover {{ background:var(--surface); }}
.badge {{ display:inline-block; padding:0.2rem 0.7rem; border-radius:999px; font-size:0.75rem; font-weight:600; }}
.run-section {{ background:var(--surface); border:1px solid var(--border); border-radius:12px; padding:1.5rem; margin:1rem 0; }}
.iteration {{ background:var(--surface2); border-radius:8px; padding:1rem; margin:0.5rem 0; font-size:0.85rem; }}
.iteration pre {{ white-space:pre-wrap; word-break:break-word; background:var(--bg); padding:0.5rem; border-radius:6px; margin:0.3rem 0; font-size:0.8rem; max-height:200px; overflow-y:auto; }}
.score-badge {{ display:inline-block; padding:0.15rem 0.5rem; border-radius:6px; font-weight:700; font-size:0.85rem; }}
.cat-bar {{ height:8px; border-radius:4px; background:var(--surface2); margin-top:0.3rem; }}
.cat-bar-fill {{ height:100%; border-radius:4px; transition:width 0.3s; }}
details {{ margin:0.5rem 0; }}
summary {{ cursor:pointer; color:var(--accent); font-weight:600; }}
</style>
</head>
<body>
<div class="container">
<h1>⚔️ Soteria — Red-Team Audit Report</h1>
<p class="subtitle">Audit ID: {report.audit_id} &nbsp;|&nbsp; Generated: {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}</p>

<div class="gate {gate_class}">CI/CD GATE: {gate_text} &nbsp;(ASR: {report.asr_percent:.1f}%)</div>

<div class="metrics">
<div class="metric"><div class="value">{report.total_objectives}</div><div class="label">Objectives Tested</div></div>
<div class="metric"><div class="value" style="color:var(--red)">{report.breached_objectives}</div><div class="label">Breached</div></div>
<div class="metric"><div class="value" style="color:{('var(--red)' if report.asr_percent > 10 else 'var(--green)')}">{report.asr_percent:.1f}%</div><div class="label">Attack Success Rate</div></div>
<div class="metric"><div class="value">{report.total_tokens:,}</div><div class="label">Tokens Used</div></div>
<div class="metric"><div class="value">${report.total_cost_usd:.4f}</div><div class="label">Estimated Cost</div></div>
</div>

{category_stats}

<h2>📋 Per-Objective Results</h2>
{''.join(objective_rows)}

</div>
</body>
</html>"""

    filepath.write_text(html_content, encoding="utf-8")
    return filepath


def _build_run_section(run: AttackRunResult) -> str:
    """Build the HTML section for a single attack run."""
    sev_color = _severity_color(run.objective.severity.value)
    score_color = _score_color(run.best_score)
    breach_text = "💥 BREACH" if run.breach_achieved else "🟢 SAFE"
    breach_style = "color:var(--red)" if run.breach_achieved else "color:var(--green)"

    iterations_html = []
    for it in run.iterations:
        score = it.judge_verdict.score if it.judge_verdict else 0
        sc = _score_color(score)
        reasoning = html.escape(
            it.judge_verdict.reasoning[:300] if it.judge_verdict else "N/A"
        )
        iterations_html.append(f"""\
<div class="iteration">
<strong>Turn {it.iteration}</strong>
<span class="score-badge" style="background:{sc}22;color:{sc}">
Score: {score}/5 — {_score_label(score)}</span>
<span class="badge" style="background:var(--surface);color:var(--text2)">
{it.mutator_type.value}</span>
<details><summary>Attack Prompt</summary><pre>{html.escape(it.attack_prompt[:500])}</pre></details>
<details><summary>Target Response</summary><pre>{html.escape(it.target_response[:500])}</pre></details>
<details><summary>Judge Reasoning</summary><pre>{reasoning}</pre></details>
</div>""")

    remediation_html = ""
    if run.remediation:
        remediation_html = f"""\
<details><summary>🔧 Auto-Remediation Patch</summary>
<div class="iteration">
<strong>Weakness:</strong> {html.escape(run.remediation.original_weakness[:300])}
<pre>{html.escape(run.remediation.hardened_system_prompt[:800])}</pre>
<strong>Explanation:</strong> {html.escape(run.remediation.explanation[:300])}
</div></details>"""

    return f"""\
<div class="run-section">
<h3>
<span class="badge" style="background:{sev_color}22;color:{sev_color}">
{run.objective.severity.value.upper()}</span>
{html.escape(run.objective.id)} — {html.escape(run.objective.title)}
<span style="{breach_style};float:right">{breach_text}</span>
</h3>
<p style="color:var(--text2);font-size:0.85rem;margin:0.3rem 0">
{html.escape(run.objective.owasp_category)} &nbsp;|&nbsp;
Best Score: <span class="score-badge" style="background:{score_color}22;color:{score_color}">
{run.best_score}/5</span> &nbsp;|&nbsp;
Turns: {len(run.iterations)} &nbsp;|&nbsp;
Tokens: {run.total_tokens:,}
</p>
{''.join(iterations_html)}
{remediation_html}
</div>"""


def _build_category_stats(report: AuditReport) -> str:
    """Build an HTML table showing breach stats per OWASP category."""
    categories: dict[str, dict] = {}
    for run in report.runs:
        cat = run.objective.owasp_category
        if cat not in categories:
            categories[cat] = {"total": 0, "breached": 0, "scores": []}
        categories[cat]["total"] += 1
        if run.breach_achieved:
            categories[cat]["breached"] += 1
        categories[cat]["scores"].append(run.best_score)

    if not categories:
        return ""

    rows = []
    for cat, stats in sorted(categories.items()):
        avg = sum(stats["scores"]) / len(stats["scores"]) if stats["scores"] else 0
        pct = (stats["breached"] / stats["total"] * 100) if stats["total"] else 0
        bar_color = _score_color(round(avg))
        rows.append(f"""\
<tr>
<td>{html.escape(cat)}</td>
<td>{stats['total']}</td>
<td style="color:{'var(--red)' if stats['breached'] > 0 else 'var(--green)'}">{stats['breached']}</td>
<td>{avg:.1f}/5</td>
<td>
<div class="cat-bar"><div class="cat-bar-fill" style="width:{pct}%;background:{bar_color}"></div></div>
{pct:.0f}%
</td>
</tr>""")

    return f"""\
<h2>📊 OWASP Category Breakdown</h2>
<table>
<tr><th>Category</th><th>Tested</th><th>Breached</th><th>Avg Score</th><th>ASR</th></tr>
{''.join(rows)}
</table>"""
