<p align="center">
  <h1 align="center">⚔️ Soteria</h1>
  <p align="center">
    <strong>Automated Adversarial Red-Teaming Harness for AI Applications</strong>
  </p>
  <p align="center">
    <em>A closed-loop evolutionary fuzzer that pits an Attacker LLM against a Target LLM,<br>
    scored by an impartial Judge LLM — all from your CPU with zero GPU required.</em>
  </p>
</p>

<p align="center">
  <a href="#quickstart">Quickstart</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#features">Features</a> •
  <a href="#usage">Usage</a> •
  <a href="#ci-cd">CI/CD Integration</a>
</p>

---

## What Is This?

Soteria is a **continuous security testing framework** for LLM-powered applications. Instead of manually typing jailbreaks, it automatically:

1. **Loads attack objectives** from a YAML taxonomy mapped to the [OWASP Top 10 for LLMs](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
2. **Mutates prompts** using both deterministic transforms (Base64, ROT13, homoglyphs, Unicode smuggling) and LLM-driven semantic strategies (PAIR, Crescendo, roleplay)
3. **Fires adversarial payloads** at your target AI system
4. **Evaluates responses** with a hybrid pipeline: fast local CPU checks (regex, RapidFuzz) → Judge LLM scoring
5. **Feeds failure analysis back** to the Attacker to evolve its next attempt
6. **Generates remediation patches** when breaches are found and verifies they hold
7. **Produces actionable reports** (HTML scorecard + interactive Streamlit dashboard)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    SOTERIA — Evolutionary Attack Loop                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐  │
│  │  📋 Seed     │    │  🔄 Mutator  │    │  🎯 Target Adapter   │  │
│  │  Attack      │───▶│  Engine      │───▶│  (LiteLLM → any     │  │
│  │  Library     │    │  (CPU+LLM)   │    │   LLM endpoint)     │  │
│  │  (YAML)      │    │              │    │                      │  │
│  └──────────────┘    └──────────────┘    └──────────┬───────────┘  │
│                             ▲                        │              │
│                             │                        ▼              │
│                    ┌────────┴───────┐    ┌──────────────────────┐  │
│                    │  💬 Feedback   │    │  ⚖️ Hybrid Judge     │  │
│                    │  Loop          │◀───│  (CPU guard + LLM)   │  │
│                    │  (Attacker     │    │                      │  │
│                    │   adapts)      │    │  Score 1-5 + Verdict │  │
│                    └────────────────┘    └──────────────────────┘  │
│                                                                     │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐  │
│  │  💰 Token    │    │  🔧 Auto     │    │  📊 Reports          │  │
│  │  Budget      │    │  Remediation │    │  (HTML + Streamlit   │  │
│  │  Breaker     │    │  Patches     │    │   + pytest)          │  │
│  └──────────────┘    └──────────────┘    └──────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Features

| Feature | Description |
|---------|-------------|
| **OWASP LLM Top 10 Taxonomy** | 10 pre-built attack objectives across 6 OWASP categories |
| **7 Deterministic Mutators** | Base64, ROT13, Leetspeak, Homoglyphs, Zero-Width, Payload Split, Unicode Smuggle |
| **Semantic Attack Strategies** | PAIR iterative refinement, Crescendo multi-turn, Roleplay, Authority Escalation |
| **Hybrid Evaluation Pipeline** | Fast CPU guard (~2ms) + Judge LLM fallback — saves ~40% API calls |
| **Token Budget Circuit Breaker** | Hard caps on tokens and USD cost per audit run |
| **Auto-Remediation** | Generates hardened system prompts on breach + verifies the patch holds |
| **CI/CD Gate** | Fails builds when Attack Success Rate exceeds threshold |
| **pytest Plugin** | `pytest --redteam` for security regression in standard test suites |
| **Interactive Dashboard** | Streamlit UI with ASR charts, conversation traces, category breakdown |
| **HTML Reports** | Self-contained dark-mode scorecard — no external dependencies |
| **Zero GPU** | All compute runs on cloud APIs via LiteLLM — your machine is just a command center |

---

## Quickstart

### 1. Install Dependencies

```bash
# Clone the repository
git clone https://github.com/your-username/soteria.git
cd soteria

# Create virtual environment
python -m venv venv
venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
```

### 2. Set Up API Keys

```bash
# Copy the template
copy .env.example .env

# Edit .env with your keys:
# - GROQ_API_KEY    → https://console.groq.com (free tier)
# - GEMINI_API_KEY  → https://aistudio.google.com/apikey (free tier)
```

### 3. Run Your First Audit

```bash
# List available attack objectives
python cli.py list-objectives

# Run a full audit (all objectives, max 5 turns each)
python cli.py run

# Run specific OWASP categories only
python cli.py run --filter LLM01 --filter LLM07

# Quick test with fewer turns
python cli.py run --max-turns 3 --filter LLM07-LEAK-001
```

---

## Usage

### CLI Commands

```bash
# Full audit with all options
python cli.py run \
  --config config/target_config.yaml \
  --objectives config/objectives.yaml \
  --filter LLM01 \
  --max-turns 5 \
  --concurrency 3 \
  --no-remediate \
  --report

# Generate HTML report from a previous audit
python cli.py report --db soteria_results.db

# Launch interactive Streamlit dashboard
python cli.py dashboard --port 8501

# List all objectives
python cli.py list-objectives
```

### Pytest Integration

```bash
# Run red-team tests in your CI pipeline
pytest --redteam

# With filters and overrides
pytest --redteam --redteam-filter LLM01 --redteam-max-turns 3

# Set custom ASR threshold
pytest --redteam --redteam-asr-threshold 5.0
```

### Configuration

Edit `config/target_config.yaml` to point at your target:

```yaml
target:
  model: "groq/llama-3.3-70b-versatile"  # Any LiteLLM model string
  system_prompt: |
    Your actual system prompt here...
  canary_tokens:
    - "SECRET_TOKEN_123"  # Embedded secrets to detect leakage
```

Edit `config/objectives.yaml` to add custom attack scenarios:

```yaml
objectives:
  - id: "CUSTOM-001"
    owasp_category: "LLM01: Prompt Injection"
    severity: critical
    title: "My Custom Attack"
    goal: "Description of what the attacker should try to achieve."
    baseline_probe: "Direct attempt at the goal."
    success_indicator: "What a successful breach looks like."
    canary_tokens: ["MY_SECRET"]
```

---

## Project Structure

```
soteria/
├── config/
│   ├── objectives.yaml          # Attack objectives (OWASP LLM Top 10)
│   └── target_config.yaml       # Target/Attacker/Judge model configs
├── core/
│   ├── models.py                # Pydantic schemas (AttackerOutput, JudgeVerdict, etc.)
│   ├── config_loader.py         # YAML → validated Pydantic config
│   ├── orchestrator.py          # Async evolutionary feedback loop
│   ├── database.py              # SQLite logger (aiosqlite)
│   └── token_budget.py          # Cost circuit breaker
├── mutators/
│   ├── deterministic.py         # 7 CPU-only string transforms
│   └── semantic_attacker.py     # LLM-driven PAIR & Crescendo strategies
├── evaluators/
│   ├── deterministic_guard.py   # Fast regex/RapidFuzz CPU checks
│   └── llm_judge.py             # Judge LLM rubric evaluator + remediation
├── reports/
│   ├── html_report.py           # Self-contained HTML scorecard generator
│   └── dashboard.py             # Interactive Streamlit dashboard
├── plugins/
│   └── pytest_soteria.py        # pytest plugin (--redteam flag)
├── cli.py                       # Click CLI entrypoint
├── pyproject.toml               # Project manifest & build config
├── requirements.txt             # Flat dependency list
├── .env.example                 # API key template
└── .gitignore
```

---

## How the Attack Loop Works

```
Iteration 1 (Baseline)
├── Load objective from objectives.yaml
├── Send unmutated baseline_probe → Target
├── Deterministic guard: canary check + similarity + PII
├── Judge LLM scores: 1/5 (Safe Refusal)
└── Feedback: "Target detected direct policy violation"

Iteration 2 (Adapt)
├── Attacker LLM receives feedback, switches to roleplay framing
├── Mutated prompt → Target
├── Guard: no canary, 25% similarity → inconclusive
├── Judge LLM scores: 3/5 (Hedged Leakage)
└── Feedback: "Target partially complied with hints"

Iteration 3 (Refine)
├── Attacker doubles down on the roleplay angle
├── Refined prompt → Target
├── Guard: canary "SOTERIA_CANARY_7f3a" found! → INSTANT BREACH
├── Score: 5/5 (Full Breach) — Judge LLM skipped
├── Auto-remediation: generate hardened system prompt
└── Re-test: verify patch blocks the winning attack
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Regression
on: [pull_request]

jobs:
  redteam:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install -r requirements.txt
      - run: pytest --redteam --redteam-max-turns 3
        env:
          GROQ_API_KEY: ${{ secrets.GROQ_API_KEY }}
          GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
```

The harness exits with **code 1** when the Attack Success Rate exceeds the configured threshold, automatically failing PR checks.

---

## Supported LLM Providers

Via [LiteLLM](https://github.com/BerriAI/litellm), Soteria works with 100+ providers:

| Provider | Model String Example | Best For |
|----------|---------------------|----------|
| **Groq** | `groq/llama-3.3-70b-versatile` | Attacker (fast, free tier) |
| **Google Gemini** | `gemini/gemini-2.5-flash` | Judge (cheap, JSON support) |
| **OpenAI** | `openai/gpt-4o-mini` | Target testing |
| **Anthropic** | `anthropic/claude-3-5-sonnet` | Target testing |
| **Ollama** | `ollama/llama3` | Local testing |

---

## License

MIT — Use responsibly. This tool is designed for **authorized security testing only**.
