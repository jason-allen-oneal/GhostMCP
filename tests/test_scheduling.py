import unittest
from datetime import UTC, datetime

from ghostmcp.scheduling import CronExpression


class CronExpressionTests(unittest.TestCase):
    def test_next_daily_occurrence(self) -> None:
        cron = CronExpression.parse("0 2 * * *")
        current = datetime(2026, 7, 15, 20, 30, tzinfo=UTC)
        self.assertEqual(
            cron.next_after(current),
            datetime(2026, 7, 16, 2, 0, tzinfo=UTC),
        )

    def test_step_and_range(self) -> None:
        cron = CronExpression.parse("*/15 9-10 * * 1-5")
        self.assertTrue(cron.matches(datetime(2026, 7, 15, 9, 30, tzinfo=UTC)))
        self.assertFalse(cron.matches(datetime(2026, 7, 18, 9, 30, tzinfo=UTC)))

    def test_restricted_day_and_weekday_use_standard_or_semantics(self) -> None:
        cron = CronExpression.parse("0 9 15 * 1")
        self.assertTrue(cron.matches(datetime(2026, 7, 15, 9, 0, tzinfo=UTC)))
        self.assertTrue(cron.matches(datetime(2026, 7, 20, 9, 0, tzinfo=UTC)))
        self.assertFalse(cron.matches(datetime(2026, 7, 16, 9, 0, tzinfo=UTC)))

    def test_invalid_expression_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            CronExpression.parse("0 2 * *")
        with self.assertRaises(ValueError):
            CronExpression.parse("61 * * * *")


if __name__ == "__main__":
    unittest.main()
