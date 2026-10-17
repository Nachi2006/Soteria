"""
Soteria — Streamlit Dashboard

Interactive vulnerability matrix with Attack Success Rate visualization,
conversation traces, and OWASP category breakdowns. Run with:

    streamlit run reports/dashboard.py
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import streamlit as st

# Ensure project root is on the path.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.database import DatabaseLogger


# ── Async helper to run DB queries in Streamlit ──────────────────────

def _run_async(coro):
    """Run an async coroutine from synchronous Streamlit code."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop and loop.is_running():
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as pool:
            return pool.submit(asyncio.run, coro).result()
    return asyncio.run(coro)


async def _fetch_audits(db_path: str):
    async with DatabaseLogger(db_path) as db:
        return await db.get_all_audits()


async def _fetch_runs(db_path: str, audit_id: str):
    async with DatabaseLogger(db_path) as db:
        return await db.get_attack_runs(audit_id)


async def _fetch_iterations(db_path: str, run_id: str):
    async with DatabaseLogger(db_path) as db:
        return await db.get_iterations(run_id)


async def _fetch_category_stats(db_path: str, audit_id: str):
    async with DatabaseLogger(db_path) as db:
        return await db.get_category_stats(audit_id)


# ── Page Config ──────────────────────────────────────────────────────

st.set_page_config(
    page_title="Soteria — Red-Team Dashboard",
    page_icon="⚔️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ───────────────────────────────────────────────────────

st.markdown("""
<style>
.stApp { background-color: #0f1117; }
.metric-card {
    background: linear-gradient(135deg, #1a1d27, #252830);
    border: 1px solid #2d3039;
    border-radius: 16px;
    padding: 1.5rem;
    text-align: center;
}
.metric-value { font-size: 2.5rem; font-weight: 700; }
.metric-label {
    font-size: 0.8rem; color: #9ca3af;
    text-transform: uppercase; letter-spacing: 0.05em;
}
.score-1 { color: #2ecc71; } .score-2 { color: #a8d855; }
.score-3 { color: #f1c40f; } .score-4 { color: #e67e22; }
.score-5 { color: #e74c3c; }
.breach-yes { color: #e74c3c; font-weight: 700; }
.breach-no { color: #2ecc71; }
</style>
""", unsafe_allow_html=True)

# ── Sidebar ──────────────────────────────────────────────────────────

st.sidebar.title("⚔️ Soteria")
st.sidebar.markdown("**Adversarial Red-Team Dashboard**")

db_path = st.sidebar.text_input(
    "Database Path",
    value="soteria_results.db",
    help="Path to the SQLite database file.",
)

if not Path(db_path).exists():
    st.warning(
        f"Database not found at `{db_path}`. "
        "Run an audit first with `python cli.py run`."
    )
    st.stop()

# ── Load Audits ──────────────────────────────────────────────────────

audits = _run_async(_fetch_audits(db_path))

if not audits:
    st.info("No audit runs found. Run `python cli.py run` to start an audit.")
    st.stop()

# Audit selector.
audit_options = {
    f"{a['audit_id']} ({a['started_at'][:19]})": a['audit_id']
    for a in audits
}
selected_label = st.sidebar.selectbox("Select Audit Run", list(audit_options.keys()))
selected_audit_id = audit_options[selected_label]
selected_audit = next(a for a in audits if a['audit_id'] == selected_audit_id)

# ── Main Header ──────────────────────────────────────────────────────

st.title("🛡️ Red-Team Audit Results")

# ── Metrics Row ──────────────────────────────────────────────────────

cols = st.columns(5)

with cols[0]:
    st.metric("Objectives Tested", selected_audit['total_objectives'])
with cols[1]:
    st.metric("Breached", selected_audit['breached_objectives'])
with cols[2]:
    asr = selected_audit['asr_percent']
    st.metric("ASR", f"{asr:.1f}%", delta_color="inverse")
with cols[3]:
    st.metric("Tokens Used", f"{selected_audit['total_tokens']:,}")
with cols[4]:
    gate = "✅ PASSED" if selected_audit['ci_gate_passed'] else "❌ FAILED"
    st.metric("CI/CD Gate", gate)

st.divider()

# ── Category Breakdown ───────────────────────────────────────────────

st.subheader("📊 OWASP Category Breakdown")

cat_stats = _run_async(_fetch_category_stats(db_path, selected_audit_id))

if cat_stats:
    cat_cols = st.columns(len(cat_stats))
    for i, cat in enumerate(cat_stats):
        with cat_cols[i]:
            cat_asr = (
                (cat['breached'] / cat['total'] * 100)
                if cat['total'] > 0 else 0
            )
            st.markdown(f"**{cat['category']}**")
            st.progress(min(cat_asr / 100, 1.0))
            st.caption(
                f"{cat['breached']}/{cat['total']} breached "
                f"| Avg: {cat['avg_score']}/5"
            )

st.divider()

# ── Per-Objective Details ────────────────────────────────────────────

st.subheader("📋 Per-Objective Results")

runs = _run_async(_fetch_runs(db_path, selected_audit_id))

for run in runs:
    obj = json.loads(run['objective_json'])
    breach = bool(run['breach_achieved'])
    breach_icon = "💥" if breach else "🟢"
    severity = obj.get('severity', 'unknown').upper()

    with st.expander(
        f"{breach_icon} **{obj['id']}** — {obj['title']} "
        f"[{severity}] — Score: {run['best_score']}/5",
        expanded=breach,
    ):
        info_cols = st.columns(4)
        with info_cols[0]:
            st.markdown(f"**Category:** {obj['owasp_category']}")
        with info_cols[1]:
            st.markdown(f"**Best Score:** {run['best_score']}/5")
        with info_cols[2]:
            st.markdown(f"**Tokens:** {run['total_tokens']:,}")
        with info_cols[3]:
            if breach:
                st.markdown(f"**Breach at Turn:** {run['breach_iteration']}")

        st.markdown(f"**Goal:** {obj['goal']}")

        # Show iterations.
        iterations = _run_async(_fetch_iterations(db_path, run['run_id']))

        for it in iterations:
            score_labels = {
                1: "🟢 Safe Refusal", 2: "🟡 Partial Refusal",
                3: "🟠 Hedged Leakage", 4: "🔴 Significant Breach",
                5: "💥 Full Breach",
            }
            verdict = json.loads(it['judge_verdict_json']) if it['judge_verdict_json'] else {}
            score = verdict.get('score', 0)
            label = score_labels.get(score, "⚪ Unknown")

            st.markdown(f"---\n**Turn {it['iteration']}** — {label} | Mutator: `{it['mutator_type']}`")

            tab1, tab2, tab3 = st.tabs(["Attack Prompt", "Target Response", "Judge Analysis"])

            with tab1:
                st.code(it['attack_prompt'][:1000], language=None)
            with tab2:
                st.code(it['target_response'][:1000], language=None)
            with tab3:
                if verdict:
                    st.json(verdict)

        # Show remediation if available.
        if run.get('remediation_json'):
            st.markdown("---\n**🔧 Auto-Remediation Patch:**")
            remediation = json.loads(run['remediation_json'])
            st.json(remediation)

# ── Footer ───────────────────────────────────────────────────────────

st.divider()
st.caption(
    "Soteria — Automated Adversarial Red-Teaming Harness | "
    f"Audit ID: {selected_audit_id}"
)
