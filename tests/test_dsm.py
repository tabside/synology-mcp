"""DSM-Client, Lese-Schutz von api_query und Auswertung im health_report, ohne echte NAS (Fake-Objekte)."""

import json
import os
import sys
from contextlib import contextmanager

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import synology_mcp as sm  # noqa: E402


# ---------------------------------------------------------------------------
# DSMClient gegen einen Fake-HTTP-Client
# ---------------------------------------------------------------------------

class FakeResponse:
    def __init__(self, payload):
        self.payload = payload
        self.extensions = {}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return b""

    def raise_for_status(self):
        pass

    def json(self):
        return self.payload


class FakeHTTP:
    def __init__(self, login_result=None):
        self.posts = []
        self.login_result = login_result or {"success": True, "data": {"sid": "SID", "synotoken": "TOK"}}

    def stream(self, method, url, data=None, headers=None, extensions=None, params=None):
        return self.post(url, data, headers, extensions)

    def post(self, url, data, headers, extensions=None):
        self.posts.append((url, data, headers))
        if data["api"] == "SYNO.API.Info":
            return FakeResponse({"success": True, "data": {
                "SYNO.Core.Share": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 3},
                "SYNO.Backup.Task": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 2},
            }})
        if data["api"] == "SYNO.API.Auth":
            return FakeResponse(self.login_result if data["method"] == "login" else {"success": True})
        if data["api"] == "SYNO.Backup.Task":
            return FakeResponse({"success": False, "error": {"code": 105}})
        return FakeResponse({"success": True, "data": {"ok": True}})


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    sm._api_info_cache.clear()
    monkeypatch.setenv("DSM_USER", "mcp")
    monkeypatch.setenv("DSM_PASSWORD", "secret")
    yield
    sm._api_info_cache.clear()


def make_client(**kw):
    http = FakeHTTP(**kw)
    return sm.DSMClient(http, "https://nas.example.com:5001/webapi"), http


def test_login_sets_sid_and_token():
    c, http = make_client()
    c.login()
    assert c.sid == "SID" and c.token == "TOK"
    assert http.posts[0][1]["session"] == "webui"


def test_login_error_is_translated():
    c, _ = make_client(login_result={"success": False, "error": {"code": 403}})
    with pytest.raises(sm.DSMError, match="2-Faktor"):
        c.login()


def test_call_uses_max_version_and_encodes_lists():
    c, http = make_client()
    c.login()
    c.call("SYNO.Core.Share", "list", additional=["hidden", "encryption"], empty=None)
    data = http.posts[-1][1]
    assert data["version"] == "3" and data["_sid"] == "SID"
    assert json.loads(data["additional"]) == ["hidden", "encryption"]
    assert "empty" not in data
    assert http.posts[-1][2] == {"X-SYNO-TOKEN": "TOK"}


def test_call_version_is_clamped():
    c, http = make_client()
    c.login()
    c.call("SYNO.Core.Share", "list", version=9)
    assert http.posts[-1][1]["version"] == "3"
    c.call("SYNO.Core.Share", "list", version="min")
    assert http.posts[-1][1]["version"] == "1"


def test_unknown_api_and_permission_error():
    c, _ = make_client()
    c.login()
    with pytest.raises(sm.DSMError, match="102"):
        c.call("SYNO.Gibt.Es.Nicht", "list")
    with pytest.raises(sm.DSMError, match="administrators"):
        c.call("SYNO.Backup.Task", "list")


def test_logout_only_once():
    c, http = make_client()
    c.login()
    c.logout()
    c.logout()
    assert sum(1 for _, d, _ in http.posts if d.get("method") == "logout") == 1


# ---------------------------------------------------------------------------
# api_query: nur lesend
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("method", ["set", "delete", "create", "backup", "reboot", "shutdown", "check", "start"])
def test_api_query_blocks_write_methods(method):
    with pytest.raises(RuntimeError, match="nicht erlaubt"):
        sm.api_query("SYNO.Core.Share", method)


@pytest.mark.parametrize("api", ["SYNO.API.Auth", "SYNO.Core.Certificate", "SYNO.FileStation.List",
                                 "SYNO.SynologyDrive.Files", "SYNO.Core.OTP", "SYNO.Core.User.PasswordPolicy",
                                 "SYNO.Foto.Browse.Item"])
def test_api_query_blocks_sensitive_apis(api):
    with pytest.raises(RuntimeError, match="gesperrt"):
        sm.api_query(api, "list")


def test_api_query_strips_reserved_params(monkeypatch):
    seen = {}

    class C:
        def call(self, api, method, version="max", **params):
            seen.update(params)
            return {}

    @contextmanager
    def fake_dsm():
        yield C()

    monkeypatch.setattr(sm, "dsm", fake_dsm)
    sm.api_query("SYNO.Core.Share", "list", params={"_sid": "x", "api": "y", "method": "z", "limit": 5})
    assert seen == {"limit": 5}


# ---------------------------------------------------------------------------
# health_report: Auffälligkeiten
# ---------------------------------------------------------------------------

def test_health_report_flags_issues(monkeypatch):
    @contextmanager
    def fake_dsm():
        yield object()

    monkeypatch.setattr(sm, "dsm", fake_dsm)
    monkeypatch.setattr(sm, "_system_info", lambda c: {"temperatur_c": 61, "temperatur_warnung": True})
    monkeypatch.setattr(sm, "_utilization", lambda c: {})
    monkeypatch.setattr(sm, "_storage", lambda c: {
        "pools": [{"id": "pool_1", "status": "degraded"}],
        "volumes": [{"pfad": "/volume1", "status": "normal", "belegt_prozent": 91.0}],
        "disks": [{"name": "Disk 1", "status": "normal", "smart_status": "normal", "temperatur_c": 40, "unc": 0},
                  {"name": "Disk 3", "status": "normal", "smart_status": "normal", "temperatur_c": 35, "unc": 82},
                  {"name": "Disk 2", "status": "crashed", "smart_status": "failing", "temperatur_c": 58,
                   "restlebensdauer_prozent": 5}],
    })
    monkeypatch.setattr(sm, "_backup_tasks", lambda c: [{"name": "Offsite", "letztes_ergebnis": "failed"},
                                                        {"name": "Lokal", "letztes_ergebnis": "done"}])
    monkeypatch.setattr(sm, "_updates", lambda c: {"update_verfuegbar": True, "version": "7.x"})

    def broken(c):
        raise RuntimeError("kaputt")

    monkeypatch.setattr(sm, "_security", broken)
    r = sm.health_report()
    text = "\n".join(r["auffaelligkeiten"])
    assert r["zustand"] == "pruefen"
    for expected in ("Temperatur-Warnung", "pool_1", "91.0 %", "Disk 2: Status crashed", "SMART failing",
                     "58 °C", "Restlebensdauer 5 %", "Disk 3: 82 unkorrigierbare", "Offsite", "Update", "security_advisor"):
        assert expected in text
    assert "Disk 1" not in text and "Lokal" not in text


def test_health_report_ok(monkeypatch):
    @contextmanager
    def fake_dsm():
        yield object()

    monkeypatch.setattr(sm, "dsm", fake_dsm)
    for name in ("_system_info", "_utilization", "_security", "_updates"):
        monkeypatch.setattr(sm, name, lambda c: {})
    monkeypatch.setattr(sm, "_storage", lambda c: {"pools": [], "volumes": [], "disks": []})
    monkeypatch.setattr(sm, "_backup_tasks", lambda c: [])
    r = sm.health_report()
    assert r["zustand"] == "ok" and r["auffaelligkeiten"] == []


def test_all_tools_registered_and_no_write_tools():
    import asyncio
    names = {t.name for t in asyncio.run(sm.list_tools())}
    assert names == set(sm.TOOL_FUNCS)
    assert not any(t.name.startswith(("set", "delete", "create", "run")) for t in asyncio.run(sm.list_tools()))


def test_tls_servername_sets_sni(monkeypatch):
    seen = []

    class H(FakeHTTP):
        def post(self, url, data, headers, extensions=None):
            seen.append(extensions)
            return super().post(url, data, headers)

    monkeypatch.setenv("DSM_TLS_SERVERNAME", "nas.example.com")
    c = sm.DSMClient(H(), "https://192.0.2.10:5001/webapi")
    c.login()
    assert seen[-1] == {"sni_hostname": "nas.example.com"}
    monkeypatch.delenv("DSM_TLS_SERVERNAME")
    c.logout()
    assert seen[-1] is None


# ---------------------------------------------------------------------------
# Zertifikats-Pinning
# ---------------------------------------------------------------------------

class _SSLObj:
    def __init__(self, der):
        self.der = der

    def getpeercert(self, binary_form):
        return self.der


class _Stream:
    def __init__(self, der):
        self.obj = _SSLObj(der)

    def get_extra_info(self, name):
        return self.obj if name == "ssl_object" else None


class _Resp:
    def __init__(self, der):
        self.extensions = {"network_stream": _Stream(der)}


def test_pin_match_and_mismatch(monkeypatch):
    der = b"zertifikat"
    fp = sm._fmt_fp(sm._sha256(der))
    monkeypatch.setenv("DSM_TLS_FINGERPRINT", fp)
    sm._check_pin(_Resp(der))  # mit Doppelpunkten
    monkeypatch.setenv("DSM_TLS_FINGERPRINT", fp.replace(":", "").lower())
    sm._check_pin(_Resp(der))  # ohne Doppelpunkte
    with pytest.raises(RuntimeError, match="passt nicht"):
        sm._check_pin(_Resp(b"anderes"))
    with pytest.raises(RuntimeError, match="kein TLS"):
        sm._check_pin(_Resp(None))


def test_no_pin_no_check(monkeypatch):
    monkeypatch.delenv("DSM_TLS_FINGERPRINT", raising=False)
    sm._check_pin(object())  # darf nichts anfassen


# ---------------------------------------------------------------------------
# cms_updates: Geräte im CMS mit Update-Information zusammenführen
# ---------------------------------------------------------------------------

class FakeCMSClient:
    def __init__(self, has_cms=True):
        self.calls = []
        self.has_cms = has_cms

    def has(self, api):
        return self.has_cms

    def call(self, api, method, version="max", _timeout=None, **params):
        self.calls.append((api, method, params))
        if api == "SYNO.CMS.DS":
            extra = lambda u: json.dumps({"unique": u, "ip": "192.0.2.1"})
            return {"total": 3, "ds_info_list": [
                {"id": 1, "hostname": "nas-a", "additional": {"model": "DS1825+", "dsm_version": "DSM 7.4-90075",
                                                              "status": 2, "extra_info": extra("synology_v1000nk_ds1825+")}},
                {"id": 2, "hostname": "nas-b", "additional": {"model": "DS1825+", "dsm_version": "DSM 7.4-90075",
                                                              "status": 2, "extra_info": extra("synology_v1000nk_ds1825+")}},
                {"id": 3, "hostname": "nas-c", "additional": {"model": "DS218", "dsm_version": "DSM 6.2-25556 Update 8",
                                                              "status": 10, "extra_info": extra("synology_rtd1296_ds218")}},
            ]}
        if api == "SYNO.Core.Upgrade.Group":
            return {"result": [
                {"unique": "synology_v1000nk_ds1825+", "current_version": "DSM 7.4-90075",
                 "latest_version": "DSM 7.4.1-90080", "type": "dsm"},
                {"unique": "synology_rtd1296_ds218", "current_version": "DSM 6.2-25556 Update 8",
                 "latest_version": "DSM 6.2-25556 Update 8", "type": "dsm"},
            ]}
        raise AssertionError(api)


def _fake_dsm(monkeypatch, client):
    @contextmanager
    def fake_dsm():
        yield client
    monkeypatch.setattr(sm, "dsm", fake_dsm)


def test_cms_updates_merges_and_dedups(monkeypatch):
    client = FakeCMSClient()
    _fake_dsm(monkeypatch, client)
    r = sm.cms_updates()
    group_call = next(p for a, m, p in client.calls if a == "SYNO.Core.Upgrade.Group")
    assert len(group_call["target"]) == 2  # gleiche Modell/Version-Kombination nur einmal angefragt
    by_host = {g["hostname"]: g for g in r["geraete"]}
    assert by_host["nas-a"]["update_verfuegbar"] and by_host["nas-a"]["neueste_version"] == "DSM 7.4.1-90080"
    assert by_host["nas-c"]["update_verfuegbar"] is False and by_host["nas-c"]["status"] == "offline"
    assert "hinweis" in by_host["nas-c"] and "hinweis" not in by_host["nas-a"]
    assert r["zusammenfassung"] == {"geraete": 3, "online": 2, "update_verfuegbar": 2}
    assert [g["hostname"] for g in r["geraete"]][:2] == ["nas-a", "nas-b"]


def test_cms_updates_only_available(monkeypatch):
    _fake_dsm(monkeypatch, FakeCMSClient())
    r = sm.cms_updates(nur_verfuegbar=True)
    assert {g["hostname"] for g in r["geraete"]} == {"nas-a", "nas-b"}


def test_cms_updates_without_cms(monkeypatch):
    _fake_dsm(monkeypatch, FakeCMSClient(has_cms=False))
    assert "hinweis" in sm.cms_updates()


def test_updates_uses_check_v3_params():
    c, http = make_client()
    sent = []
    orig = http.post

    def post(url, data, headers, extensions=None):
        if data["api"] == "SYNO.API.Info":
            return FakeResponse({"success": True, "data": {
                "SYNO.Core.Upgrade.Server": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 4}}})
        if data["api"] == "SYNO.Core.Upgrade.Server":
            sent.append(data)
            return FakeResponse({"success": True, "data": {"update": {"available": True, "version": "7.4.1"}}})
        return orig(url, data, headers, extensions)

    http.post = post
    c.login()
    r = sm._updates(c)
    assert r["update_verfuegbar"] is True and r["version"] == "7.4.1"
    assert sent[0]["method"] == "check" and sent[0]["version"] == "3"
    assert sent[0]["need_auto_smallupdate"] == "true" and sent[0]["user_reading"] == "true"
