"""Zertifikats-Pinning (DSM_TLS_FINGERPRINT) gegen einen lokalen HTTPS-Server mit selbstsigniertem Zertifikat.

Kern der Prüfung: Bei falschem oder gewechseltem Zertifikat scheitert die Verbindung im TLS-Handshake,
d.h. der Login (mit Passwort) erreicht die Gegenstelle nie. Braucht das Paket cryptography (nur Tests)."""

import datetime
import http.server
import json
import os
import ssl
import sys
import threading
from contextlib import contextmanager

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import synology_mcp as sm  # noqa: E402

x509 = pytest.importorskip("cryptography.x509")
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402


def _make_cert(tmp_path, name: str, san: list[str] | None = None) -> tuple[str, str, bytes]:
    """Selbstsigniertes Zertifikat; liefert (cert.pem, key.pem, DER)."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=1)))
    if san:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(d) for d in san]), critical=False)
    cert = builder.sign(key, hashes.SHA256())
    cert_file, key_file = tmp_path / f"{name}.pem", tmp_path / f"{name}.key"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return str(cert_file), str(key_file), cert.public_bytes(serialization.Encoding.DER)


class _Handler(http.server.BaseHTTPRequestHandler):
    """Antwortet auf alles wie ein DSM-Login/-Logout mit Erfolg und protokolliert jeden Request."""
    requests: list[tuple[str, str]] = []

    def _answer(self):
        type(self).requests.append((self.command, self.path))
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        body = json.dumps({"success": True, "data": {"sid": "SID", "synotoken": "TOK"}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = _answer

    def log_message(self, *a):
        pass


@contextmanager
def _https_server(cert_file: str, key_file: str):
    handler = type("Handler", (_Handler,), {"requests": []})
    srv = http.server.HTTPServer(("127.0.0.1", 0), handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_file, key_file)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield srv.server_address[1], handler.requests
    finally:
        srv.shutdown()
        srv.server_close()


@pytest.fixture(autouse=True)
def env(monkeypatch):
    sm._pinned_cert_cache.clear()
    sm._api_info_cache.clear()
    monkeypatch.setenv("DSM_HOST", "127.0.0.1")
    monkeypatch.setenv("DSM_USER", "mcp")
    monkeypatch.setenv("DSM_PASSWORD", "geheim")
    monkeypatch.delenv("DSM_TLS_SERVERNAME", raising=False)
    yield
    sm._pinned_cert_cache.clear()


def test_pin_matches_login_goes_through(tmp_path, monkeypatch):
    cert, key, der = _make_cert(tmp_path, "nas")
    with _https_server(cert, key) as (port, requests):
        monkeypatch.setenv("DSM_PORT", str(port))
        monkeypatch.setenv("DSM_TLS_FINGERPRINT", sm._fmt_fp(sm._sha256(der)))
        with sm.dsm() as c:
            assert c.sid == "SID"
        assert [m for m, _ in requests] == ["POST", "POST"]  # Login und Logout
        assert sm._pinned_cert_cache  # Zertifikat ist pro Fingerprint gecacht


def test_wrong_pin_aborts_before_any_request(tmp_path, monkeypatch):
    cert, key, der = _make_cert(tmp_path, "nas")
    with _https_server(cert, key) as (port, requests):
        monkeypatch.setenv("DSM_PORT", str(port))
        monkeypatch.setenv("DSM_TLS_FINGERPRINT", sm._sha256(b"anderes Zertifikat"))
        with pytest.raises(RuntimeError, match="passt nicht"):
            with sm.dsm():
                pass
        assert requests == []  # nur Handshake, kein Login


def test_swapped_cert_fails_in_handshake(tmp_path, monkeypatch):
    """TOCTOU-Fall: Zertifikat beim Holen korrekt, danach legt die Gegenstelle ein anderes vor
    (z.B. MITM auf einer neuen TCP-Verbindung). Der Login darf dort nie ankommen."""
    import httpx
    cert_a, key_a, der_a = _make_cert(tmp_path, "nas")
    cert_b, key_b, _ = _make_cert(tmp_path, "mitm")
    monkeypatch.setenv("DSM_TLS_FINGERPRINT", sm._sha256(der_a))
    with _https_server(cert_a, key_a) as (port_a, _):
        monkeypatch.setenv("DSM_PORT", str(port_a))
        sm._pinned_context()  # holt und cacht Zertifikat A
    with _https_server(cert_b, key_b) as (port_b, requests_b):
        monkeypatch.setenv("DSM_PORT", str(port_b))
        with pytest.raises(httpx.ConnectError, match="(?i)certificate"):
            with sm.dsm():
                pass
        assert requests_b == []


def test_servername_enforces_hostname_check(tmp_path, monkeypatch):
    import httpx
    cert, key, der = _make_cert(tmp_path, "nas", san=["nas.example.com"])
    monkeypatch.setenv("DSM_TLS_FINGERPRINT", sm._sha256(der))
    with _https_server(cert, key) as (port, requests):
        monkeypatch.setenv("DSM_PORT", str(port))
        # Name passt zum SAN
        monkeypatch.setenv("DSM_TLS_SERVERNAME", "nas.example.com")
        with sm.dsm():
            pass
        assert len(requests) == 2
        # Name passt nicht: Handshake scheitert, kein weiterer Request
        monkeypatch.setenv("DSM_TLS_SERVERNAME", "falsch.example.com")
        with pytest.raises(httpx.ConnectError):
            with sm.dsm():
                pass
        assert len(requests) == 2


def test_pinned_context_trusts_only_pinned_cert(tmp_path, monkeypatch):
    cert, key, der = _make_cert(tmp_path, "nas")
    with _https_server(cert, key) as (port, _):
        monkeypatch.setenv("DSM_PORT", str(port))
        monkeypatch.setenv("DSM_TLS_FINGERPRINT", sm._sha256(der))
        ctx = sm._pinned_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is False
    assert ctx.verify_flags & ssl.VERIFY_X509_PARTIAL_CHAIN
    assert ctx.cert_store_stats()["x509"] == 1


def test_tls_check_reports_pin(tmp_path, monkeypatch):
    cert, key, der = _make_cert(tmp_path, "nas", san=["nas.example.com"])
    with _https_server(cert, key) as (port, requests):
        monkeypatch.setenv("DSM_PORT", str(port))
        monkeypatch.setenv("DSM_TLS_FINGERPRINT", sm._sha256(der))
        out = sm.tls_check()
    assert out["sha256"] == sm._fmt_fp(sm._sha256(der))
    assert out["pinning"] == "passt" and out["selbstsigniert"] is True
    assert out["san"] == ["nas.example.com"]
    assert out["pruefung"].startswith("fehlgeschlagen")  # selbstsigniert, keine CA
    assert requests == []
