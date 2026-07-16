"""Small, dependency-free five-field cron scheduler."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta


@dataclass(frozen=True)
class CronField:
    values: frozenset[int]
    wildcard: bool = False

    @classmethod
    def parse(cls, expression: str, minimum: int, maximum: int) -> CronField:
        values: set[int] = set()
        components = [part.strip() for part in expression.split(",")]
        if any(not part for part in components):
            raise ValueError("Empty cron field component")
        wildcard = expression.strip() == "*"
        for part in components:
            base, separator, step_text = part.partition("/")
            step = int(step_text) if separator else 1
            if step < 1:
                raise ValueError("Cron step must be positive")
            if base == "*":
                start, end = minimum, maximum
            elif "-" in base:
                start_text, range_separator, end_text = base.partition("-")
                if not range_separator or "-" in end_text:
                    raise ValueError(f"Invalid cron range: {base}")
                start, end = int(start_text), int(end_text)
            else:
                start = end = int(base)
            if start < minimum or end > maximum or start > end:
                raise ValueError(
                    f"Cron value outside {minimum}-{maximum}: {part}"
                )
            values.update(range(start, end + 1, step))
        return cls(frozenset(values), wildcard=wildcard)

    def matches(self, value: int) -> bool:
        return value in self.values


@dataclass(frozen=True)
class CronExpression:
    minute: CronField
    hour: CronField
    day: CronField
    month: CronField
    weekday: CronField

    @classmethod
    def parse(cls, expression: str) -> CronExpression:
        parts = expression.split()
        if len(parts) != 5:
            raise ValueError("Cron expression must contain five fields")
        return cls(
            minute=CronField.parse(parts[0], 0, 59),
            hour=CronField.parse(parts[1], 0, 23),
            day=CronField.parse(parts[2], 1, 31),
            month=CronField.parse(parts[3], 1, 12),
            weekday=CronField.parse(parts[4], 0, 6),
        )

    def matches(self, value: datetime) -> bool:
        candidate = value.astimezone(UTC)
        cron_weekday = (candidate.weekday() + 1) % 7
        day_matches = self.day.matches(candidate.day)
        weekday_matches = self.weekday.matches(cron_weekday)
        if self.day.wildcard or self.weekday.wildcard:
            calendar_matches = day_matches and weekday_matches
        else:
            # Standard cron semantics use OR when both fields are restricted.
            calendar_matches = day_matches or weekday_matches
        return (
            self.minute.matches(candidate.minute)
            and self.hour.matches(candidate.hour)
            and self.month.matches(candidate.month)
            and calendar_matches
        )

    def next_after(self, value: datetime) -> datetime:
        candidate = value.astimezone(UTC).replace(second=0, microsecond=0) + timedelta(
            minutes=1
        )
        limit = candidate + timedelta(days=366 * 2)
        while candidate <= limit:
            if self.matches(candidate):
                return candidate
            candidate += timedelta(minutes=1)
        raise ValueError("Cron expression has no occurrence within two years")
