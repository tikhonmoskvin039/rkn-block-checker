from unittest.mock import patch, MagicMock

from rkn_checker.network import check_tcp, check_tls


class TestCheckTcp:
    @patch("rkn_checker.network.socket.create_connection")
    def test_success_returns_true_and_time(self, mock_conn):
        mock_conn.return_value.__enter__ = MagicMock(return_value=None)
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)
        ok, ms, err = check_tcp("example.com")
        assert ok is True
        assert ms is not None
        assert err is None

    @patch("rkn_checker.network.socket.create_connection", side_effect=__import__("socket").timeout("t"))
    def test_timeout_returns_false_timeout_string(self, mock_conn):
        ok, ms, err = check_tcp("example.com")
        assert ok is False
        assert err == "timeout"

    @patch("rkn_checker.network.socket.create_connection", side_effect=ConnectionResetError("r"))
    def test_reset_returns_false_reset_string(self, mock_conn):
        ok, ms, err = check_tcp("example.com")
        assert ok is False
        assert "reset" in err


class TestCheckTls:
    @patch("rkn_checker.network.socket.create_connection")
    def test_connection_aborted_returns_reset_string(self, mock_conn):
        mock_conn.side_effect = ConnectionAbortedError("abort")
        ok, ms, cn, err = check_tls("example.com")
        assert ok is False
        assert "reset" in err

    @patch("rkn_checker.network.socket.create_connection", side_effect=__import__("socket").timeout("t"))
    def test_timeout_returns_timeout(self, mock_conn):
        ok, ms, cn, err = check_tls("example.com")
        assert ok is False
        assert err == "timeout"

class TestProxyArgValidation:
    """The proxy URL is validated at the network layer so that core.py
    callers don't have to. Empty/None means 'no proxy'; an unknown scheme
    is rejected explicitly so the user gets a clear error rather than a
    cryptic socks failure deep in the call stack."""

    def test_open_socket_without_proxy_uses_create_connection(self):
        from unittest.mock import patch
        from rkn_checker.network import _open_socket
        with patch("rkn_checker.network.socket.create_connection") as mock_conn:
            _open_socket("example.com", 443, 5.0, proxy_url=None)
            mock_conn.assert_called_once_with(("example.com", 443), timeout=5.0)

    def test_open_socket_rejects_unsupported_scheme(self):
        import pytest
        from rkn_checker.network import _open_socket
        with pytest.raises(ValueError, match="unsupported proxy scheme"):
            _open_socket("example.com", 443, 5.0, proxy_url="ftp://x:1")

    def test_open_socket_rejects_missing_port(self):
        import pytest
        from rkn_checker.network import _open_socket
        with pytest.raises(ValueError, match="missing host or port"):
            _open_socket("example.com", 443, 5.0, proxy_url="socks5://192.168.1.1")