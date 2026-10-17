"""
Soteria — Token Budget & Cost Circuit Breaker

Tracks cumulative prompt/completion tokens across all LLM calls in a run
and raises BudgetExhaustedError when hard caps are exceeded. This prevents
automated loops from burning through API credits unchecked.
"""

from __future__ import annotations

import threading

from core.models import TokenBudgetConfig, TokenUsage


class BudgetExhaustedError(Exception):
    """Raised when the token or cost budget has been exceeded."""

    def __init__(self, reason: str, usage: TokenUsage):
        self.reason = reason
        self.usage = usage
        super().__init__(f"Budget exhausted: {reason}")


class TokenBudgetTracker:
    """Thread-safe cumulative token and cost tracker with circuit breaker.

    Usage:
        tracker = TokenBudgetTracker(config)
        tracker.record(usage)        # After each LLM call
        tracker.check_budget()       # Raises BudgetExhaustedError if over limit
        tracker.remaining_tokens()   # Tokens left before hard cap
    """

    def __init__(self, config: TokenBudgetConfig):
        self._config = config
        self._lock = threading.Lock()
        self._total_prompt_tokens = 0
        self._total_completion_tokens = 0
        self._total_tokens = 0
        self._total_cost_usd = 0.0
        self._call_count = 0

    def record(self, usage: TokenUsage) -> None:
        """Record token usage from a single LLM call.

        Args:
            usage: TokenUsage from the completed LLM call.
        """
        with self._lock:
            self._total_prompt_tokens += usage.prompt_tokens
            self._total_completion_tokens += usage.completion_tokens
            self._total_tokens += usage.total_tokens
            self._total_cost_usd += usage.cost_usd
            self._call_count += 1

    def check_budget(self) -> None:
        """Check if the budget has been exceeded and raise if so.

        Raises:
            BudgetExhaustedError: If token or cost limit is breached.
        """
        with self._lock:
            if self._total_tokens >= self._config.max_total_tokens:
                raise BudgetExhaustedError(
                    reason=(
                        f"Token limit reached: {self._total_tokens:,} / "
                        f"{self._config.max_total_tokens:,} tokens"
                    ),
                    usage=self.snapshot(),
                )
            if self._total_cost_usd >= self._config.max_cost_usd:
                raise BudgetExhaustedError(
                    reason=(
                        f"Cost limit reached: ${self._total_cost_usd:.4f} / "
                        f"${self._config.max_cost_usd:.4f}"
                    ),
                    usage=self.snapshot(),
                )

    def remaining_tokens(self) -> int:
        """Return the number of tokens remaining before the hard cap."""
        with self._lock:
            return max(0, self._config.max_total_tokens - self._total_tokens)

    def remaining_cost(self) -> float:
        """Return the USD budget remaining."""
        with self._lock:
            return max(0.0, self._config.max_cost_usd - self._total_cost_usd)

    def snapshot(self) -> TokenUsage:
        """Return a snapshot of cumulative usage."""
        with self._lock:
            return TokenUsage(
                prompt_tokens=self._total_prompt_tokens,
                completion_tokens=self._total_completion_tokens,
                total_tokens=self._total_tokens,
                cost_usd=self._total_cost_usd,
                model=f"aggregate ({self._call_count} calls)",
            )

    @property
    def call_count(self) -> int:
        """Number of LLM calls recorded."""
        with self._lock:
            return self._call_count

    def __repr__(self) -> str:
        s = self.snapshot()
        return (
            f"TokenBudget(tokens={s.total_tokens:,}/{self._config.max_total_tokens:,}, "
            f"cost=${s.cost_usd:.4f}/${self._config.max_cost_usd:.4f}, "
            f"calls={self._call_count})"
        )
