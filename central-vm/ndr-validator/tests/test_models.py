from app.models import CheckResult, Status, score_from_checks, worst_status


def test_score_and_worst_status():
    checks = [
        CheckResult("a", "a", "x", Status.OK, "ok"),
        CheckResult("b", "b", "x", Status.WARN, "warn"),
        CheckResult("c", "c", "x", Status.UNKNOWN, "unknown"),
    ]
    assert worst_status([c.status for c in checks]) == Status.WARN
    assert score_from_checks(checks) == 90
