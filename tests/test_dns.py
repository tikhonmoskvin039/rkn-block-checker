from unittest.mock import patch, MagicMock

from rkn_checker.dns import (
    resolve_doh,
    resolve_doh_all,
    resolve_system,
    resolve_system_all,
)


def _addrinfo(*ips: str):
    """Build a getaddrinfo-shaped return value with the given IPv4 addresses.

    Each entry is (family, type, proto, canonname, sockaddr) where sockaddr
    is (ip, port) for IPv4. We only care about the IP, so the rest is filler.
    """
    import socket
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in ips]


class TestResolveSystemAll:
    """The all-addresses helper is the new source of truth — single-IP
    helpers are derived from it. These tests pin down its behaviour
    independently."""

    @patch("rkn_checker.dns.socket.getaddrinfo",
           return_value=[__import__("socket").AF_INET])  # placeholder, patched below
    def test_returns_every_ip_in_response(self, mock_getaddr):
        mock_getaddr.return_value = _addrinfo("1.2.3.4", "5.6.7.8", "9.10.11.12")
        ips = resolve_system_all("example.com")
        assert ips == frozenset({"1.2.3.4", "5.6.7.8", "9.10.11.12"})

    @patch("rkn_checker.dns.socket.getaddrinfo")
    def test_dedupes_repeated_ips(self, mock_getaddr):
        # The OS resolver can hand back duplicates across SOCK_STREAM/SOCK_DGRAM
        # entries. Caller compares sets, so we must not leak that detail.
        mock_getaddr.return_value = _addrinfo("1.2.3.4", "1.2.3.4", "5.6.7.8")
        assert resolve_system_all("example.com") == frozenset({"1.2.3.4", "5.6.7.8"})

    @patch("rkn_checker.dns.socket.getaddrinfo",
           side_effect=__import__("socket").gaierror("fail"))
    def test_returns_empty_on_gaierror(self, mock_getaddr):
        assert resolve_system_all("example.com") == frozenset()

    @patch("rkn_checker.dns.socket.getaddrinfo")
    def test_requests_only_ipv4(self, mock_getaddr):
        # Mixing in IPv6 results would muddy mismatch comparison; verify
        # that the underlying call is constrained to AF_INET.
        import socket
        mock_getaddr.return_value = _addrinfo("1.2.3.4")
        resolve_system_all("example.com")
        assert mock_getaddr.call_args[1]["family"] == socket.AF_INET


class TestResolveDohAll:
    @patch("rkn_checker.dns.requests.get")
    def test_returns_every_a_record(self, mock_get):
        resp = MagicMock()
        resp.ok = True
        resp.json.return_value = {"Answer": [
            {"type": 1, "data": "9.9.9.9"},
            {"type": 1, "data": "8.8.8.8"},
            {"type": 1, "data": "1.1.1.1"},
        ]}
        mock_get.return_value = resp
        assert resolve_doh_all("example.com") == frozenset({
            "9.9.9.9", "8.8.8.8", "1.1.1.1",
        })

    @patch("rkn_checker.dns.requests.get")
    def test_ignores_non_a_record_types(self, mock_get):
        # CNAME (type 5) gets followed by upstream resolvers — for our
        # comparison only the final A records matter.
        resp = MagicMock()
        resp.ok = True
        resp.json.return_value = {"Answer": [
            {"type": 5, "data": "alias.example.com."},
            {"type": 1, "data": "9.9.9.9"},
            {"type": 28, "data": "::1"},  # AAAA
        ]}
        mock_get.return_value = resp
        assert resolve_doh_all("example.com") == frozenset({"9.9.9.9"})

    @patch("rkn_checker.dns.requests.get")
    def test_returns_empty_on_http_error(self, mock_get):
        resp = MagicMock()
        resp.ok = False
        mock_get.return_value = resp
        assert resolve_doh_all("example.com") == frozenset()

    @patch("rkn_checker.dns.requests.get",
           side_effect=__import__("requests").exceptions.RequestException("net"))
    def test_returns_empty_on_request_exception(self, mock_get):
        assert resolve_doh_all("example.com") == frozenset()

    @patch("rkn_checker.dns.requests.get")
    def test_returns_empty_on_no_answer_field(self, mock_get):
        resp = MagicMock()
        resp.ok = True
        resp.json.return_value = {}  # NXDOMAIN-shape
        mock_get.return_value = resp
        assert resolve_doh_all("example.com") == frozenset()


class TestSingleIpHelpers:
    """The legacy single-IP helpers are now thin wrappers. We just need to
    confirm they pull from the *_all variants and pick deterministically."""

    @patch("rkn_checker.dns.resolve_system_all",
           return_value=frozenset({"5.5.5.5", "1.1.1.1", "9.9.9.9"}))
    def test_resolve_system_picks_lowest_for_stability(self, _):
        # Sorted-first means tests don't flake based on set hash order, and
        # rkn-check output stays the same between runs against the same host.
        assert resolve_system("example.com") == "1.1.1.1"

    @patch("rkn_checker.dns.resolve_system_all", return_value=frozenset())
    def test_resolve_system_returns_none_on_empty(self, _):
        assert resolve_system("example.com") is None

    @patch("rkn_checker.dns.resolve_doh_all",
           return_value=frozenset({"9.9.9.9", "8.8.8.8"}))
    def test_resolve_doh_picks_lowest(self, _):
        assert resolve_doh("example.com") == "8.8.8.8"

    @patch("rkn_checker.dns.resolve_doh_all", return_value=frozenset())
    def test_resolve_doh_returns_none_on_empty(self, _):
        assert resolve_doh("example.com") is None

    @patch("rkn_checker.dns.resolve_doh_all", return_value=frozenset({"1.1.1.1"}))
    def test_resolve_doh_passes_timeout(self, mock_all):
        resolve_doh("example.com", timeout=2.5)
        assert mock_all.call_args[1]["timeout"] == 2.5
