from unittest.mock import patch

from rkn_checker.core import check_url
from rkn_checker.http import HttpProbe
from rkn_checker.models import Confidence, Verdict


def _ipset(*ips: str) -> frozenset[str]:
    return frozenset(ips)


def _patches(
    *,
    sys_ips=("1.2.3.4",),
    doh_ips=("1.2.3.4",),
    tcp=(True, 10.0, None),
    tls=(True, 20.0, "example.com", None),
    http=None,
):
    """Build the patch list for a check_url call.

    `sys_ips` / `doh_ips` accept any iterable. Pass an empty tuple to
    simulate a resolution failure (NXDOMAIN, network error, etc.) — that
    used to be `sys_ip=None` in the single-IP era.
    """
    if http is None:
        http = HttpProbe(status_code=200, elapsed_ms=100.0, body_snippet="<html>ok</html>")
    return [
        patch("rkn_checker.core.dns_mod.resolve_system_all",
              return_value=_ipset(*sys_ips)),
        patch("rkn_checker.core.dns_mod.resolve_doh_all",
              return_value=_ipset(*doh_ips)),
        patch("rkn_checker.core.network.check_tcp", return_value=tcp),
        patch("rkn_checker.core.network.check_tls", return_value=tls),
        patch("rkn_checker.core.http_mod.fetch", return_value=http),
    ]


def _run_with(patches):
    for p in patches:
        p.start()
    try:
        return check_url("test", "https://example.com/")
    finally:
        for p in patches:
            p.stop()


class TestVerdictPath:
    def test_happy_path_yields_ok(self):
        r = _run_with(_patches())
        assert r.verdict == Verdict.OK
        assert r.confidence == Confidence.HIGH

    def test_dns_block_when_system_fails_but_doh_works(self):
        r = _run_with(_patches(sys_ips=(), doh_ips=("1.2.3.4",)))
        assert r.verdict == Verdict.DNS_BLOCK
        assert r.confidence == Confidence.HIGH

    def test_down_when_neither_resolver_finds_domain(self):
        r = _run_with(_patches(sys_ips=(), doh_ips=()))
        assert r.verdict == Verdict.DOWN
        assert r.confidence == Confidence.LOW

    def test_disjoint_dns_sets_flag_mismatch(self):
        # Real rewriting case: not a single overlap between the two answers.
        r = _run_with(_patches(sys_ips=("1.1.1.1",), doh_ips=("2.2.2.2",)))
        assert r.dns_mismatch is True
        assert r.verdict == Verdict.OK
        assert r.confidence == Confidence.MEDIUM

    def test_tcp_timeout_yields_timeout_verdict(self):
        r = _run_with(_patches(tcp=(False, None, "timeout")))
        assert r.verdict == Verdict.TIMEOUT
        assert r.confidence == Confidence.LOW

    def test_tcp_reset_yields_tcp_reset_verdict(self):
        r = _run_with(_patches(tcp=(False, None, "connection reset")))
        assert r.verdict == Verdict.TCP_RESET
        assert r.confidence == Confidence.MEDIUM

    def test_tcp_other_failure_yields_down(self):
        r = _run_with(_patches(tcp=(False, None, "OSError: no route to host")))
        assert r.verdict == Verdict.DOWN

    def test_tls_reset_is_classified_as_tls_block(self):
        r = _run_with(_patches(tls=(False, None, None, "connection reset during TLS")))
        assert r.verdict == Verdict.TLS_BLOCK
        assert r.confidence == Confidence.MEDIUM

    def test_tls_timeout_is_also_a_tls_block(self):
        r = _run_with(_patches(tls=(False, None, None, "timeout")))
        assert r.verdict == Verdict.TLS_BLOCK
        assert r.confidence == Confidence.MEDIUM

    def test_http_451_is_an_http_stub(self):
        probe = HttpProbe(status_code=451, elapsed_ms=50.0, body_snippet="")
        r = _run_with(_patches(http=probe))
        assert r.verdict == Verdict.HTTP_STUB
        assert r.confidence == Confidence.HIGH

    def test_http_stub_marker_in_body(self):
        probe = HttpProbe(status_code=200, elapsed_ms=50.0,
                          body_snippet="доступ ограничен по решению")
        r = _run_with(_patches(http=probe))
        assert r.verdict == Verdict.HTTP_STUB
        assert r.confidence == Confidence.HIGH

    def test_http_timeout_yields_timeout(self):
        probe = HttpProbe(error="timeout", timed_out=True)
        r = _run_with(_patches(http=probe))
        assert r.verdict == Verdict.TIMEOUT

    def test_normal_200_is_ok(self):
        probe = HttpProbe(status_code=200, elapsed_ms=50.0,
                          body_snippet="<html><body>welcome</body></html>")
        r = _run_with(_patches(http=probe))
        assert r.verdict == Verdict.OK
        assert r.confidence == Confidence.HIGH

    def test_doh_failure_is_noted(self):
        r = _run_with(_patches(sys_ips=("1.2.3.4",), doh_ips=()))
        assert any("DoH lookup failed" in n for n in r.notes)

    def test_doh_failure_continues_probing(self):
        r = _run_with(_patches(sys_ips=("1.2.3.4",), doh_ips=()))
        assert r.verdict == Verdict.OK


class TestDnsSetComparison:
    """Multi-A-record sites (vk.ru, lenta.ru, anything CDN-fronted) used to
    misfire as 'transparent DNS rewriting' on every other run because the
    OS resolver rotates the answer order and we compared only the first IP
    from each side. The fix is to compare *sets*: a real rewrite means the
    two sets don't overlap at all; any shared IP means it's load balancing,
    not poisoning."""

    def test_overlapping_pools_do_not_flag_mismatch(self):
        # Real-world example shape: sys returns three IPs in one rotation,
        # DoH returns the same three in a different order. Old code would
        # see sys_ip=A, doh_ip=B and flag mismatch every time.
        r = _run_with(_patches(
            sys_ips=("81.19.72.32", "81.19.72.33", "81.19.72.34"),
            doh_ips=("81.19.72.34", "81.19.72.32", "81.19.72.33"),
        ))
        assert r.dns_mismatch is False
        assert r.verdict == Verdict.OK
        assert r.confidence == Confidence.HIGH

    def test_partial_overlap_does_not_flag_mismatch(self):
        # CDN edge nodes can return slightly different subsets to different
        # resolvers (especially with EDNS Client Subnet). One shared IP is
        # enough to confirm we're talking to the same service.
        r = _run_with(_patches(
            sys_ips=("1.1.1.1", "2.2.2.2"),
            doh_ips=("2.2.2.2", "3.3.3.3"),
        ))
        assert r.dns_mismatch is False
        assert r.verdict == Verdict.OK

    def test_completely_disjoint_pools_flag_mismatch(self):
        r = _run_with(_patches(
            sys_ips=("1.1.1.1", "2.2.2.2"),
            doh_ips=("9.9.9.9", "8.8.8.8"),
        ))
        assert r.dns_mismatch is True
        # Note text should hint at the disjointness so users can debug.
        assert any("disjoint" in n for n in r.notes)

    def test_single_ip_match_does_not_flag_mismatch(self):
        # The original simple case still works: one IP each side, identical.
        r = _run_with(_patches(sys_ips=("1.2.3.4",), doh_ips=("1.2.3.4",)))
        assert r.dns_mismatch is False

    def test_full_address_pools_recorded_in_result(self):
        # Both sets must be on the result so JSON consumers can audit the
        # decision. Sorted for determinism in tests and in tool output.
        r = _run_with(_patches(
            sys_ips=("3.3.3.3", "1.1.1.1"),
            doh_ips=("2.2.2.2",),
        ))
        assert r.sys_ips == ["1.1.1.1", "3.3.3.3"]
        assert r.doh_ips == ["2.2.2.2"]
        # And the legacy single-IP fields stay populated for backward compat.
        assert r.sys_ip == "1.1.1.1"
        assert r.doh_ip == "2.2.2.2"
