"""
Verify iter_check_urls yields results as soon as they're ready, not all at
once at the end. This is a regression guard for the streaming UX — the whole
point is that the user sees rows tick by, not a wall of text after a long
silence.
"""
import time
from unittest.mock import patch

from rkn_checker.core import iter_check_urls


def _slow_check_url(name, url, timeout, identify=False, proxy_url=None):
    """Stand-in for check_url that takes a deterministic amount of time
    based on the target name. 'a' is fastest, 'd' is slowest."""
    delays = {"a": 0.05, "b": 0.10, "c": 0.15, "d": 0.20}
    time.sleep(delays.get(name, 0.05))
    from rkn_checker.models import CheckResult, Verdict
    return CheckResult(name=name, url=url, verdict=Verdict.OK)


class TestStreamingOrder:
    def test_results_arrive_in_completion_order_not_input_order(self):
        # Input order is d, c, b, a — but a finishes first, d last.
        urls = {
            "d": "https://d.example/",
            "c": "https://c.example/",
            "b": "https://b.example/",
            "a": "https://a.example/",
        }
        with patch("rkn_checker.core.check_url", side_effect=_slow_check_url):
            received = [r.name for r in iter_check_urls(urls, max_workers=4, timeout=1.0)]
        assert received == ["a", "b", "c", "d"]

    def test_first_result_arrives_well_before_last(self):
        # If results were buffered until the end, t_first would equal t_last.
        # With proper streaming, t_first should land near the fastest target.
        urls = {
            "a": "https://a.example/",
            "d": "https://d.example/",
        }
        timestamps = []
        with patch("rkn_checker.core.check_url", side_effect=_slow_check_url):
            t0 = time.monotonic()
            for r in iter_check_urls(urls, max_workers=2, timeout=1.0):
                timestamps.append(time.monotonic() - t0)

        # 'a' takes 0.05s, 'd' takes 0.20s. First arrival should be << last.
        # Generous bounds to avoid flaky CI: first < 0.12, last > 0.15.
        assert timestamps[0] < 0.12, f"first result too late: {timestamps[0]:.3f}s"
        assert timestamps[-1] > 0.15, f"last result too early: {timestamps[-1]:.3f}s"
        assert timestamps[-1] - timestamps[0] > 0.08, (
            f"results bunched up — looks buffered: {timestamps}"
        )

    def test_empty_input_yields_nothing(self):
        with patch("rkn_checker.core.check_url", side_effect=_slow_check_url):
            assert list(iter_check_urls({}, max_workers=4, timeout=1.0)) == []


class TestParallelWrapperPreservesOrder:
    def test_check_urls_parallel_returns_input_order_despite_streaming(self):
        from rkn_checker.core import check_urls_parallel
        urls = {
            "d": "https://d.example/",
            "c": "https://c.example/",
            "b": "https://b.example/",
            "a": "https://a.example/",
        }
        with patch("rkn_checker.core.check_url", side_effect=_slow_check_url):
            results = check_urls_parallel(urls, max_workers=4, timeout=1.0)
        # Order in the returned list must match input order, even though
        # 'a' finished first internally.
        assert [r.name for r in results] == ["d", "c", "b", "a"]


class TestExceptionHandling:
    def test_unexpected_exception_yields_unknown_verdict(self):
        from rkn_checker.models import CheckResult, Verdict

        def _boom(name, url, timeout, identify=False, proxy_url=None):
            raise RuntimeError("kaboom")

        urls = {"x": "https://x.example/"}
        with patch("rkn_checker.core.check_url", side_effect=_boom):
            results = list(iter_check_urls(urls, max_workers=1, timeout=1.0))
        assert len(results) == 1
        assert results[0].verdict == Verdict.UNKNOWN
        assert "kaboom" in results[0].notes[0]
