"""Deterministic daily statistics aggregation (Phase 3.9).

The service owns reporting-window semantics and derives the small read-side
record returned by the API. It does not score, decide, route, or modify any
Wazuh policy. All counts come from :class:`StatsRepository` aggregate queries.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, time, timedelta

from ..models.records import (
    DailyStatsRecord,
    DailyStatsTopRule,
    DailyStatsTuningSuggestion,
    DailyStatsVolumes,
)
from ..models.repositories import StatsRepository, as_utc

UTC_TIMEZONE = "UTC"


def reporting_window(report_date: date) -> tuple[datetime, datetime]:
    """Return the half-open UTC calendar-day window for ``report_date``."""
    start = datetime.combine(report_date, time.min, tzinfo=UTC)
    return start, start + timedelta(days=1)


def previous_utc_date(now: datetime | None = None) -> date:
    """Return the UTC calendar day immediately before ``now``.

    A timezone-naive value is treated as UTC, matching the repository's
    timestamp convention. Exactly midnight therefore selects the preceding
    date without an off-by-one boundary.
    """
    current = as_utc(now or datetime.now(UTC))
    return (current - timedelta(days=1)).date()


class StatsService:
    """Build one aggregate daily statistics record from a repository."""

    def __init__(self, repository: StatsRepository) -> None:
        self._repository = repository

    def daily(
        self,
        *,
        report_date: date | None = None,
        now: datetime | None = None,
    ) -> DailyStatsRecord:
        """Aggregate the explicit date, or the previous UTC date by default."""
        selected_date = report_date or previous_utc_date(now)
        start, end = reporting_window(selected_date)

        alert_count = self._repository.count_alerts(start, end)
        incident_count = self._repository.count_incidents(start, end)
        feedback_count, false_positive_count = self._repository.feedback_counts(start, end)
        false_positive_rate = (
            round(false_positive_count / feedback_count, 4) if feedback_count else 0.0
        )

        return DailyStatsRecord(
            date=selected_date,
            timezone=UTC_TIMEZONE,
            volumes=DailyStatsVolumes(
                alerts=alert_count,
                incidents=incident_count,
                feedback=feedback_count,
            ),
            false_positive_rate=false_positive_rate,
            false_positive_count=false_positive_count,
            feedback_count=feedback_count,
            top_rules=[
                DailyStatsTopRule(rule_id=rule_id, count=count)
                for rule_id, count in self._repository.top_rules(start, end)
            ],
            tuning_suggestions=[
                DailyStatsTuningSuggestion(
                    rule_id=rule_id,
                    agent_id=agent_id,
                    false_positive_count=false_positive_count_for_pair,
                )
                for rule_id, agent_id, false_positive_count_for_pair in self._repository.tuning_suggestions(
                    start, end
                )
            ],
        )


__all__ = ["StatsService", "previous_utc_date", "reporting_window"]
