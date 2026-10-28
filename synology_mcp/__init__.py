"""
Synology MCP Server für eine Synology-NAS (DSM 7) über die DSM Web API.
Aufbau wie esxi-mcp/pbs-mcp: roher mcp.server.Server, Tool-Funktionen in TOOL_FUNCS.
Läuft ausschliesslich als Docker-Container mit Streamable-HTTP-Transport hinter einem
Reverse-Proxy und erfordert MCP_AUTH_TOKEN. Ein lokaler Betrieb (stdio/uvx) ist nicht vorgesehen.

Alle Werte kommen aus Umgebungsvariablen (DSM_HOST, DSM_PORT, DSM_USER, DSM_PASSWORD,
DSM_VERIFY_SSL, DSM_TLS_SERVERNAME, DSM_TLS_FINGERPRINT, MCP_AUTH_TOKEN, MCP_HOST, MCP_PORT, Schwellwerte) - keine Secrets im Code.

Der Server ist grundsätzlich LESEND:
- Einzige Ausnahme ist cms_dsm_update (DSM-Update über das CMS verteilen): ohne confirm=true nur
  Vorschau, ausgeführt wird nur mit MCP_ALLOW_WRITE=true im Container.
- api_query (generischer Lesezugriff) lässt nur lesende Methoden zu (Allowlist) und sperrt
  APIs mit Zugangsdaten, Schlüsseln oder Dateiinhalten (Blocklist).
- Jeder Tool-Aufruf meldet sich an und danach wieder ab, es bleiben keine Sessions offen.
"""

import asyncio
import json
import os
import re
import ssl
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any

from mcp.server import Server
from mcp.types import Tool, TextContent


# Version = <Major.Minor>.<Patch>, Patch wird aus der Git-Historie gezählt (wie esxi-mcp).
_REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_VERSION_PATHS = ['Dockerfile', 'requirements.txt', 'pyproject.toml', 'synology_mcp/', '.github/workflows/docker-publish.yml']


def _version_base() -> str:
    raw = ""
    try:
        import tomllib
        with open(os.path.join(_REPO_DIR, "pyproject.toml"), "rb") as f:
            raw = tomllib.load(f)["project"]["version"]
    except Exception:
        try:
            from importlib.metadata import version
            raw = version("synology-mcp")
        except Exception:
            pass
    return ".".join(raw.split(".")[:2]) if raw else "0.0"


def _read_version() -> str:
    env_version = os.environ.get("APP_VERSION", "").strip()
    if env_version:
        return env_version
    base = _version_base()
    try:
        import subprocess
        count = subprocess.run(
            ["git", "rev-list", "--count", "HEAD", "--", *_VERSION_PATHS],
            cwd=_REPO_DIR, capture_output=True, text=True, timeout=5, check=True,
        ).stdout.strip()
        if count.isdigit():
            return f"{base}.{count}"
    except Exception:
        pass
    return f"{base}.0-dev"


__version__ = _read_version()


# ---------------------------------------------------------------------------
# Konfiguration
# ---------------------------------------------------------------------------

def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _float_env(name: str, default: float) -> float:
    try:
        return float(_env(name) or default)
    except ValueError:
        return default


def _verify():
    """httpx-verify: True, False oder SSL-Kontext mit eigener CA-Datei."""
    raw = _env("DSM_VERIFY_SSL", "true")
    if raw.lower() == "false":
        return False
    if raw.lower() == "true":
        return True
    return ssl.create_default_context(cafile=raw)


def _base_url() -> str:
    host = _env("DSM_HOST")
    if not host:
        raise RuntimeError("DSM_HOST muss gesetzt sein (Umgebungsvariable)")
    scheme = "https" if _env("DSM_HTTPS", "true").lower() != "false" else "http"
    return f"{scheme}://{host}:{_env('DSM_PORT', '5001')}/webapi"


# ---------------------------------------------------------------------------
# Zertifikats-Pinning (DSM_TLS_FINGERPRINT = SHA-256 des Server-Zertifikats)
#
# Das Pinning greift im TLS-Handshake, nicht erst nach der Antwort: Das Zertifikat der NAS
# wird einmal ohne Zugangsdaten geholt (reiner Handshake, keine Anwendungsdaten), mit dem
# Fingerprint verglichen und dann als einzige Vertrauensbasis (CA) in den SSL-Kontext geladen.
# Jede weitere Verbindung, auch der Login mit Passwort, scheitert damit bereits beim Handshake,
# wenn die Gegenstelle ein anderes Zertifikat vorlegt - es gehen keine Daten an einen MITM.
# ---------------------------------------------------------------------------

_pinned_cert_cache: dict[str, str] = {}  # Fingerprint -> PEM (ein Fingerprint gehört zu genau einem Zertifikat)
_pinned_cert_lock = threading.Lock()


def _fingerprint_pin() -> str:
    return _env("DSM_TLS_FINGERPRINT").replace(":", "").replace(" ", "").lower()


def _sha256(der: bytes) -> str:
    import hashlib
    return hashlib.sha256(der).hexdigest()


def _fmt_fp(hexstr: str) -> str:
    return ":".join(hexstr[i:i + 2] for i in range(0, len(hexstr), 2)).upper()


def _fetch_server_cert(host: str, port: int, servername: str) -> tuple[bytes, str]:
    """Holt das Server-Zertifikat (DER) und die TLS-Version per reinem Handshake ohne Prüfung.
    Es werden keine Anwendungsdaten gesendet, nur die ClientHello/SNI."""
    import socket
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=servername) as tls:
            return tls.getpeercert(binary_form=True), tls.version()


def _pinned_pem() -> str:
    """Zertifikat der NAS holen, gegen DSM_TLS_FINGERPRINT prüfen und als PEM liefern (gecacht pro Fingerprint)."""
    import hmac
    pin = _fingerprint_pin()
    with _pinned_cert_lock:
        pem = _pinned_cert_cache.get(pin)
        if pem is None:
            host, port = _env("DSM_HOST"), int(_env("DSM_PORT", "5001"))
            if not host:
                raise RuntimeError("DSM_HOST muss gesetzt sein (Umgebungsvariable)")
            der, _ = _fetch_server_cert(host, port, _env("DSM_TLS_SERVERNAME") or host)
            if not der:
                raise RuntimeError("DSM_TLS_FINGERPRINT gesetzt, aber kein TLS-Zertifikat lesbar (DSM_HTTPS=false?)")
            if not hmac.compare_digest(_sha256(der), pin):
                raise RuntimeError(f"Zertifikat der NAS passt nicht zu DSM_TLS_FINGERPRINT (erhalten {_fmt_fp(_sha256(der))}) - Verbindung abgebrochen")
            pem = ssl.DER_cert_to_PEM_cert(der)
            _pinned_cert_cache[pin] = pem
    return pem


def _pinned_context() -> ssl.SSLContext:
    """SSL-Kontext, der ausschliesslich dem gepinnten Zertifikat vertraut (CA-Pinning).
    Hostname-Prüfung nur, wenn DSM_TLS_SERVERNAME gesetzt ist; sonst identifiziert der Fingerprint
    das Zertifikat (selbstsignierte DSM-Zertifikate enthalten den Hostnamen oft nicht)."""
    ctx = ssl.create_default_context(cadata=_pinned_pem())
    # Das Blattzertifikat selbst ist der Vertrauensanker, keine Kette bis zu einer Root-CA nötig
    ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = bool(_env("DSM_TLS_SERVERNAME"))
    return ctx


def _check_pin(resp) -> None:
    """Zusätzliche Kontrolle nach dem Handshake: Das Zertifikat der tatsächlich genutzten Verbindung
    muss dem Pin entsprechen. Der eigentliche Schutz ist der Kontext aus _pinned_context()."""
    pin = _fingerprint_pin()
    if not pin:
        return
    stream = resp.extensions.get("network_stream")
    ssl_obj = stream.get_extra_info("ssl_object") if stream else None
    der = ssl_obj.getpeercert(True) if ssl_obj else None
    if not der:
        raise RuntimeError("DSM_TLS_FINGERPRINT gesetzt, aber kein TLS-Zertifikat lesbar (DSM_HTTPS=false?)")
    import hmac
    if not hmac.compare_digest(_sha256(der), pin):
        raise RuntimeError(f"Zertifikat der NAS passt nicht zu DSM_TLS_FINGERPRINT (erhalten {_fmt_fp(_sha256(der))}) - Verbindung abgebrochen")


# ---------------------------------------------------------------------------
# DSM-Fehlercodes
# ---------------------------------------------------------------------------

_COMMON_ERRORS = {
    100: "Unbekannter Fehler",
    101: "Parameter fehlt oder ungültig (API, Methode oder Version)",
    102: "API existiert nicht (Paket nicht installiert?)",
    103: "Methode existiert nicht",
    104: "Version wird nicht unterstützt",
    105: "Keine Berechtigung (User muss in der Gruppe administrators sein)",
    106: "Session abgelaufen",
    107: "Session unterbrochen (doppelte Anmeldung)",
    119: "Session-ID nicht gefunden",
}

_AUTH_ERRORS = {
    400: "Benutzername oder Passwort falsch",
    401: "Konto deaktiviert",
    402: "Keine Berechtigung",
    403: "2-Faktor-Code erforderlich (für den MCP-User 2FA deaktivieren)",
    404: "2-Faktor-Code ungültig",
    406: "2-Faktor-Pflicht aktiv (für den MCP-User 2FA deaktivieren)",
    407: "IP-Adresse durch Auto-Block gesperrt",
    408: "Passwort abgelaufen, Änderung nötig",
    409: "Passwort abgelaufen",
    410: "Passwort muss geändert werden",
}


class DSMError(RuntimeError):
    def __init__(self, api: str, method: str, code: int, auth: bool = False):
        self.api, self.method, self.code = api, method, code
        text = (_AUTH_ERRORS if auth else {}).get(code) or _COMMON_ERRORS.get(code) or "siehe DSM-API-Doku"
        super().__init__(f"DSM-Fehler {code} bei {api}.{method}: {text}")


# ---------------------------------------------------------------------------
# Verbindung (pro Aufruf eine Session, danach Logout - kein Session-Leak auf der NAS)
# ---------------------------------------------------------------------------

_api_info_cache: dict[str, dict] = {}
_api_info_lock = threading.Lock()


class DSMClient:
    def __init__(self, http, base_url: str):
        self.http = http
        self.base = base_url
        self.sid: str | None = None
        self.token: str | None = None

    def _post(self, path: str, data: dict, timeout: float | None = None) -> dict:
        headers = {"X-SYNO-TOKEN": self.token} if self.token else {}
        # DSM_TLS_SERVERNAME: per IP verbinden, Zertifikat aber gegen den externen Namen prüfen (SNI)
        servername = _env("DSM_TLS_SERVERNAME")
        extensions = {"sni_hostname": servername} if servername else {}
        if timeout:
            # httpx-Timeout pro Request (z.B. Update-Abfrage beim Synology-Server, die länger dauert)
            extensions["timeout"] = {"connect": timeout, "read": timeout, "write": timeout, "pool": timeout}
        # Als Stream, damit das Zertifikat der Verbindung gelesen werden kann, solange sie offen ist
        with self.http.stream("POST", f"{self.base}/{path}", data=data, headers=headers,
                              extensions=extensions or None) as resp:
            _check_pin(resp)
            resp.raise_for_status()
            resp.read()
        return resp.json()

    def api_info(self) -> dict[str, dict]:
        with _api_info_lock:
            if not _api_info_cache:
                res = self._post("query.cgi", {"api": "SYNO.API.Info", "version": "1", "method": "query", "query": "ALL"})
                if not res.get("success"):
                    raise DSMError("SYNO.API.Info", "query", res.get("error", {}).get("code", 100))
                _api_info_cache.update(res["data"])
            return _api_info_cache

    def login(self) -> None:
        user, pwd = _env("DSM_USER"), os.environ.get("DSM_PASSWORD", "")
        if not (user and pwd):
            raise RuntimeError("DSM_USER und DSM_PASSWORD müssen gesetzt sein (Umgebungsvariablen)")
        res = self._post("entry.cgi", {
            "api": "SYNO.API.Auth", "version": "6", "method": "login",
            "account": user, "passwd": pwd, "session": "webui", "format": "sid",
            "enable_syno_token": "yes",
        })
        if not res.get("success"):
            raise DSMError("SYNO.API.Auth", "login", res.get("error", {}).get("code", 100), auth=True)
        self.sid = res["data"]["sid"]
        self.token = res["data"].get("synotoken")

    def logout(self) -> None:
        if self.sid:
            try:
                self._post("entry.cgi", {"api": "SYNO.API.Auth", "version": "6", "method": "logout",
                                         "session": "webui", "_sid": self.sid})
            except Exception:
                pass
            self.sid = None

    def has(self, api: str) -> bool:
        return api in self.api_info()

    def call(self, api: str, method: str, version: str | int = "max", _timeout: float | None = None, **params) -> Any:
        info = self.api_info().get(api)
        if not info:
            raise DSMError(api, method, 102)
        if version == "max":
            ver = info["maxVersion"]
        elif version == "min":
            ver = info["minVersion"]
        else:
            ver = max(info["minVersion"], min(int(version), info["maxVersion"]))
        data = {"api": api, "version": str(ver), "method": method, "_sid": self.sid}
        for k, v in params.items():
            if v is None:
                continue
            data[k] = json.dumps(v) if isinstance(v, (list, dict, bool)) else str(v)
        res = self._post(info.get("path", "entry.cgi"), data, timeout=_timeout)
        if not res.get("success"):
            raise DSMError(api, method, res.get("error", {}).get("code", 100))
        return res.get("data", {})


@contextmanager
def dsm():
    import httpx
    # Bei Pinning ersetzt das gepinnte Zertifikat die CA-Prüfung (z.B. selbstsigniertes DSM-Zertifikat im LAN);
    # die Prüfung passiert im Handshake, bevor Login-Daten gesendet werden
    verify = _pinned_context() if _fingerprint_pin() else _verify()
    limits = httpx.Limits(max_connections=1, max_keepalive_connections=1)
    with httpx.Client(verify=verify, timeout=30, limits=limits, trust_env=False) as http:
        client = DSMClient(http, _base_url())
        client.login()
        try:
            yield client
        finally:
            client.logout()


# ---------------------------------------------------------------------------
# Hilfen
# ---------------------------------------------------------------------------

def _num(v) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _gb(num_bytes) -> float | None:
    n = _num(num_bytes)
    return round(n / 1024 ** 3, 1) if n is not None else None


def _pct(used, total) -> float | None:
    u, t = _num(used), _num(total)
    return round(100 * u / t, 1) if u is not None and t else None


def _remain_life(disk: dict):
    rl = disk.get("remain_life")
    if isinstance(rl, dict):  # DSM 7: {"trustable": ..., "value": ...}
        return rl.get("value") if rl.get("value", -1) != -1 else None
    return rl if rl not in (None, -1) else None


def _epoch(v) -> str | None:
    n = _num(v)
    if not n:
        return v
    return datetime.fromtimestamp(n, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _ok(status) -> bool:
    return str(status).lower() in ("normal", "safe", "")


# ---------------------------------------------------------------------------
# Lesende Tools
# ---------------------------------------------------------------------------

def get_version() -> dict:
    return {"version": __version__, "git_sha": _env("GIT_SHA", "unbekannt")}


def _decode_der(der: bytes) -> dict:
    """DER-Zertifikat ohne Zusatzpakete lesbar machen (über die ssl-Testfunktion der Standardbibliothek)."""
    import tempfile
    pem = ssl.DER_cert_to_PEM_cert(der)
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=True) as f:
        f.write(pem)
        f.flush()
        info = ssl._ssl._test_decode_cert(f.name)
    flat = lambda rdns: ", ".join(f"{k}={v}" for rdn in rdns for k, v in rdn)
    return {"subject": flat(info.get("subject", ())), "issuer": flat(info.get("issuer", ())),
            "san": [v for k, v in info.get("subjectAltName", ()) if k == "DNS"],
            "gueltig_ab": info.get("notBefore"), "gueltig_bis": info.get("notAfter"),
            "selbstsigniert": info.get("subject") == info.get("issuer")}


def tls_check() -> dict:
    """Zeigt, welches Zertifikat die NAS ausliefert, und ob die normale Prüfung klappt. Sendet keine Zugangsdaten."""
    import socket
    host, port = _env("DSM_HOST"), int(_env("DSM_PORT", "5001"))
    if not host:
        raise RuntimeError("DSM_HOST muss gesetzt sein (Umgebungsvariable)")
    servername = _env("DSM_TLS_SERVERNAME") or host
    der, tls_version = _fetch_server_cert(host, port, servername)
    out = {"verbindung": f"{host}:{port}", "sni": servername, "tls": tls_version, **_decode_der(der),
           "sha256": _fmt_fp(_sha256(der))}
    try:
        vctx = _verify()
        if vctx is False:
            out["pruefung"] = "DSM_VERIFY_SSL=false, keine Prüfung"
        else:
            if vctx is True:
                vctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=10) as sock:
                with vctx.wrap_socket(sock, server_hostname=servername):
                    pass
            out["pruefung"] = "ok"
    except Exception as e:
        out["pruefung"] = f"fehlgeschlagen: {e}"
    pin = _fingerprint_pin()
    if pin:
        out["pinning"] = "passt" if pin == _sha256(der) else "passt NICHT"
    return out


def _system_info(c: DSMClient) -> dict:
    out: dict[str, Any] = {}
    if c.has("SYNO.DSM.Info"):
        d = c.call("SYNO.DSM.Info", "getinfo")
        out.update({
            "modell": d.get("model"), "dsm_version": d.get("version_string"),
            "ram_mb": d.get("ram"), "temperatur_c": d.get("temperature"),
            "temperatur_warnung": d.get("temperature_warn"),
            "uptime_stunden": round(d["uptime"] / 3600, 1) if isinstance(d.get("uptime"), (int, float)) else None,
            "zeitzone": d.get("time_zone_desc") or d.get("time_zone"),
        })
    if c.has("SYNO.Core.System"):
        d = c.call("SYNO.Core.System", "info")
        out.update({k: v for k, v in {
            "modell": out.get("modell") or d.get("model"),
            "dsm_version": out.get("dsm_version") or d.get("firmware_ver"),
            "cpu": " ".join(str(x) for x in (d.get("cpu_vendor"), d.get("cpu_family"), d.get("cpu_series")) if x) or None,
            "cpu_kerne": d.get("cpu_cores"),
            "ram_mb": out.get("ram_mb") or d.get("ram_size"),
            "temperatur_c": out.get("temperatur_c") if out.get("temperatur_c") is not None else d.get("sys_temp"),
            "temperatur_warnung": out.get("temperatur_warnung") if out.get("temperatur_warnung") is not None else d.get("temperature_warning"),
            "systemzeit": d.get("time"),
            "uptime": d.get("up_time"),
        }.items() if v is not None})
    return out


def system_info() -> dict:
    """Modell, DSM-Version, CPU, RAM, Temperatur, Uptime (auch als Verbindungstest)."""
    with dsm() as c:
        return _system_info(c)


def _utilization(c: DSMClient) -> dict:
    d = c.call("SYNO.Core.System.Utilization", "get")
    cpu, mem = d.get("cpu", {}), d.get("memory", {})
    total_kb, avail_kb = _num(mem.get("total_real")), _num(mem.get("avail_real"))
    net = next((n for n in d.get("network", []) if n.get("device") == "total"), None)
    return {
        "cpu_prozent": sum(int(cpu.get(k) or 0) for k in ("user_load", "system_load", "other_load")),
        # DSM liefert die Load mal 100 (225 = 2.25)
        "load_1_5_15": [round(v / 100, 2) if isinstance(v, (int, float)) else v
                        for v in (cpu.get("1min_load"), cpu.get("5min_load"), cpu.get("15min_load"))],
        "ram_prozent": mem.get("real_usage"),
        "ram_total_gb": round(total_kb / 1024 ** 2, 1) if total_kb else None,
        "ram_frei_gb": round(avail_kb / 1024 ** 2, 1) if avail_kb is not None else None,
        "ram_cache_gb": round((_num(mem.get("cached")) or 0) / 1024 ** 2, 1),
        "swap_prozent": mem.get("swap_usage"),
        "netz_rx_kbs": round(net["rx"] / 1024, 1) if net and isinstance(net.get("rx"), (int, float)) else None,
        "netz_tx_kbs": round(net["tx"] / 1024, 1) if net and isinstance(net.get("tx"), (int, float)) else None,
        "disks_io": [{"disk": x.get("display_name") or x.get("device"), "auslastung_prozent": x.get("utilization"),
                      "lesen_kbs": round(x["read_byte"] / 1024, 1) if isinstance(x.get("read_byte"), (int, float)) else None,
                      "schreiben_kbs": round(x["write_byte"] / 1024, 1) if isinstance(x.get("write_byte"), (int, float)) else None}
                     for x in d.get("disk", {}).get("disk", [])],
    }


def utilization() -> dict:
    """Aktuelle Auslastung: CPU, RAM, Swap, Netzwerk, Disk-I/O."""
    with dsm() as c:
        return _utilization(c)


def _storage(c: DSMClient) -> dict:
    d = c.call("SYNO.Storage.CGI.Storage", "load_info")
    pools = [{
        "id": p.get("id"), "status": p.get("status"),
        "raid": p.get("device_type") or p.get("raidType"),
        "groesse_gb": _gb((p.get("size") or {}).get("total")),
        # Anteil des Pools, der Volumes zugewiesen ist (nicht die Datenbelegung, die steht beim Volume)
        "zugewiesen_prozent": _pct((p.get("size") or {}).get("used"), (p.get("size") or {}).get("total")),
        "disks": p.get("disks"),
    } for p in d.get("storagePools", [])]
    volumes = [{
        "id": v.get("id"), "pfad": v.get("vol_path"), "status": v.get("status"),
        "dateisystem": v.get("fs_type"), "pool": v.get("pool_path"),
        "groesse_gb": _gb((v.get("size") or {}).get("total")),
        "belegt_gb": _gb((v.get("size") or {}).get("used")),
        "frei_gb": _gb(_num((v.get("size") or {}).get("total") or 0) - _num((v.get("size") or {}).get("used") or 0))
        if (v.get("size") or {}).get("total") else None,
        "belegt_prozent": _pct((v.get("size") or {}).get("used"), (v.get("size") or {}).get("total")),
    } for v in d.get("volumes", [])]
    disks = [{
        "id": x.get("id"), "name": x.get("longName") or x.get("name"),
        "modell": " ".join(str(y).strip() for y in (x.get("vendor"), x.get("model")) if y),
        "typ": x.get("diskType"), "ssd": x.get("isSsd"),
        "groesse_gb": _gb(x.get("size_total")), "status": x.get("status"),
        "smart_status": x.get("smart_status"), "temperatur_c": x.get("temp"),
        "restlebensdauer_prozent": _remain_life(x),
        "bad_sector_grenze_ueberschritten": x.get("exceed_bad_sector_thr"),
        "restlebensdauer_unter_grenze": x.get("below_remain_life_thr"),
        "unc": x.get("unc"), "firmware": x.get("firm"),
        "pool": x.get("used_by"),
    } for x in d.get("disks", [])]
    return {"pools": pools, "volumes": volumes, "disks": disks,
            "hot_spares": len(d.get("hotSpares") or [])}


def storage() -> dict:
    """Speicherpools, Volumes (Belegung) und Disks (Status, SMART, Temperatur, Restlebensdauer)."""
    with dsm() as c:
        return _storage(c)


def _backup_tasks(c: DSMClient) -> list[dict]:
    if not c.has("SYNO.Backup.Task"):
        return []
    tasks = c.call("SYNO.Backup.Task", "list", version="min").get("task_list", [])
    out = []
    for t in tasks:
        entry = {"id": t.get("task_id"), "name": t.get("name"), "zustand": t.get("state"),
                 "status": t.get("status"), "ziel": t.get("target_type") or t.get("transfer_type"),
                 "typ": t.get("data_type") or t.get("type")}
        try:
            s = c.call("SYNO.Backup.Task", "status", version="min", task_id=t.get("task_id"), blOnline="false",
                       additional=["last_bkp_time", "next_bkp_time", "last_bkp_result", "last_bkp_progress"])
            entry.update({"letztes_backup": s.get("last_bkp_time"), "letztes_ergebnis": s.get("last_bkp_result"),
                          "naechstes_backup": s.get("next_bkp_time"), "status": s.get("status", entry["status"]),
                          "zustand": s.get("state", entry["zustand"])})
        except Exception as e:
            entry["fehler_status"] = str(e)
        out.append(entry)
    return out


def backup_tasks() -> list[dict]:
    """Hyper-Backup-Aufgaben mit letztem Ergebnis, letzter und nächster Ausführung."""
    with dsm() as c:
        return _backup_tasks(c)


def _updates(c: DSMClient) -> dict:
    # Gleicher Aufruf wie die Systemsteuerung (Version 3 mit diesen Parametern). Ohne sie
    # antwortet DSM 7.4 mit Fehler 119. "check" fragt nur ab und lädt oder installiert nichts.
    d = c.call("SYNO.Core.Upgrade.Server", "check", version=3, _timeout=120,
               user_reading=True, need_auto_smallupdate=True, need_promotion=True)
    upd = d.get("update", d)
    return {"update_verfuegbar": upd.get("available"), "version": upd.get("version"),
            "neustart_noetig": upd.get("reboot"), "typ": upd.get("type")}


def updates() -> dict:
    """Prüft, ob ein DSM-Update verfügbar ist (installiert nichts)."""
    with dsm() as c:
        return _updates(c)


# Statuscodes der Geräte im Central Management System (aus dem CMS-Webinterface)
_CMS_STATUS = {
    0: "unbekannt", 1: "nicht konfiguriert", 2: "online", 3: "nicht installiert", 4: "Update läuft",
    5: "System verloren", 6: "startet", 7: "prüft Kontingent", 8: "startet Dienste",
    9: "wartet auf Update", 10: "offline", 11: "tritt bei", 12: "tritt aus", 13: "Neustart",
    14: "heruntergefahren", 15: "nicht erreichbar", 16: "Ruhezustand",
}


def _cms_devices(c: DSMClient) -> list[dict]:
    """Alle Geräte im CMS mit Modell, DSM-Version, Status und Modellkennung (unique)."""
    out, offset = [], 0
    while True:
        d = c.call("SYNO.CMS.DS", "list", version=1, offset=offset, limit=100,
                   additional=["model", "dsm_version", "status", "extra_info", "gluster_role",
                               "host", "http_port", "build_number", "smallfix_number"])
        items = d.get("ds_info_list", [])
        for x in items:
            a = x.get("additional") or {}
            extra = a.get("extra_info") or {}
            if isinstance(extra, str):
                try:
                    extra = json.loads(extra)
                except ValueError:
                    extra = {}
            out.append({"id": x.get("id"), "hostname": x.get("hostname"), "modell": a.get("model"),
                        "dsm_version": a.get("dsm_version"), "status_code": a.get("status"),
                        "status": _CMS_STATUS.get(a.get("status"), f"Code {a.get('status')}"),
                        "unique": extra.get("unique"), "gluster_role": a.get("gluster_role"),
                        "host": a.get("host"), "http_port": a.get("http_port"),
                        "build_number": a.get("build_number"), "self": bool(extra.get("self"))})
        offset += len(items)
        if not items or offset >= int(d.get("total") or 0):
            return out


def _model_key(unique: str | None) -> str | None:
    # unique = "synology_<plattform>_<modell>", das CMS vergleicht nur den Modellteil
    parts = (unique or "").split("_")
    return parts[2] if len(parts) > 2 else None


def cms_updates(nur_verfuegbar: bool = False) -> dict:
    """DSM-Updates aller Geräte im Central Management System (wie CMS > Update).
    Fragt den Synology-Updateserver nur ab, lädt und installiert nichts."""
    with dsm() as c:
        if not c.has("SYNO.CMS.DS"):
            return {"hinweis": "Central Management System ist auf dieser NAS nicht installiert oder nicht erreichbar"}
        devices = _cms_devices(c)
        seen, targets = set(), []
        for dev in devices:
            key = (dev["unique"], dev["dsm_version"])
            if dev["unique"] and dev["dsm_version"] and key not in seen:
                seen.add(key)
                targets.append({"dsm_version": dev["dsm_version"], "unique": dev["unique"]})
        infos = []
        if targets:
            # Wie im CMS-Webinterface: SYNO.Core.Upgrade.Group.info fragt pro Modell und Version
            # beim Synology-Updateserver nach, das kann dauern
            infos = c.call("SYNO.Core.Upgrade.Group", "info", version=1, _timeout=300,
                           target=targets).get("result", [])

    geraete = []
    for dev in devices:
        info = next((i for i in infos
                     if _model_key(i.get("unique")) == _model_key(dev["unique"])
                     and i.get("current_version") == dev["dsm_version"]), None)
        latest = (info or {}).get("latest_version")
        entry = {"hostname": dev["hostname"], "modell": dev["modell"], "status": dev["status"],
                 "dsm_version": dev["dsm_version"], "neueste_version": latest,
                 "update_verfuegbar": bool(latest) and latest != dev["dsm_version"] if info else None}
        if dev["status_code"] != 2:
            entry["hinweis"] = "Gerät nicht online, Update kann im CMS nicht verteilt werden"
        if info is None:
            entry["hinweis_update"] = "keine Update-Information vom Synology-Server erhalten"
        geraete.append(entry)

    geraete.sort(key=lambda g: (not g["update_verfuegbar"], (g["hostname"] or "").lower()))
    zusammenfassung = {
        "geraete": len(geraete),
        "online": sum(1 for d in devices if d["status_code"] == 2),
        "update_verfuegbar": sum(1 for g in geraete if g["update_verfuegbar"]),
    }
    if nur_verfuegbar:
        geraete = [g for g in geraete if g["update_verfuegbar"]]
    return {"zusammenfassung": zusammenfassung, "geraete": geraete}


# ---------------------------------------------------------------------------
# CMS: DSM-Update an verwaltete Geräte verteilen (einziges schreibendes Tool)
#
# Gleicher Ablauf wie CMS > Aufgabe > DSM-Aktualisierung im Webinterface: Das CMS legt eine
# Aufgabe "dsm_update" an, lädt die .pat-Datei auf die Zielgeräte und startet dort das Update
# (mit Neustart). Die .pat-Dateien müssen bereits auf der CMS-NAS liegen.
# Schutz: ohne confirm=true nur Vorschau; ausgeführt wird nur, wenn MCP_ALLOW_WRITE=true gesetzt ist;
# offline-Geräte, die CMS-NAS selbst, ältere/gleiche Builds und Major-Sprünge (z.B. 6.x -> 7.x,
# nur mit allow_major=true) werden abgelehnt.
# ---------------------------------------------------------------------------

def _write_allowed() -> bool:
    return _env("MCP_ALLOW_WRITE", "false").lower() == "true"


def _parse_dsm(v: str | None) -> dict | None:
    """'DSM 7.4.1-90080 Update 1' / '7.4-90080' -> {major, build, nano}"""
    m = re.search(r"(\d+)(?:\.\d+)*-(\d+)(?:\s+Update\s+(\d+))?", v or "")
    if not m:
        return None
    return {"major": int(m.group(1)), "build": int(m.group(2)), "nano": int(m.group(3) or 0)}


def _patch_candidates(dev: dict, build: int, patch_dir: str) -> list[str]:
    d = patch_dir.rstrip("/")
    out = [f"{d}/DSM_{dev['modell']}_{build}.pat"]
    if dev.get("unique"):
        out.append(f"{d}/{dev['unique']}_{build}.pat")
    return out


def _patch_info(c: DSMClient, paths: list[str]) -> dict[str, dict]:
    """Prüft .pat-Dateien einzeln: Das CMS beantwortet einen Aufruf mit einer nicht vorhandenen
    Datei komplett mit Fehler 101, darum pro Datei ein Aufruf; 101 = Datei fehlt."""
    out = {}
    for p in paths:
        try:
            res = c.call("SYNO.CMS.PolicyEditor.Patch", "info", version=2, _timeout=120,
                         files=[{"path": p, "isdir": False}])
        except DSMError as e:
            if e.code == 101:
                out[p] = {"path": p, "success": False, "exist": False}
                continue
            raise
        for f in res.get("filestat", []):
            out[f.get("path")] = f
    return out


def _parse_schedule(schedule: str | None) -> dict | None:
    if not schedule:
        return None
    try:
        dt = datetime.strptime(schedule.strip(), "%Y-%m-%d %H:%M")
    except ValueError:
        raise RuntimeError("schedule im Format 'YYYY-MM-DD HH:MM' (Zeitzone der CMS-NAS) angeben oder leer lassen für sofort")
    return {"year": dt.year, "month": dt.month, "day": dt.day, "hour": dt.hour, "minute": dt.minute}


def cms_dsm_update(hostnames: list, patch_files: dict = None, patch_dir: str = None,
                   schedule: str = None, allow_major: bool = False, confirm: bool = False) -> dict:
    """DSM-Update über das CMS an ausgewählte Geräte verteilen. Ohne confirm nur Vorschau."""
    if not hostnames:
        raise RuntimeError("hostnames angeben (Liste der Geräte wie in cms_updates)")
    patch_files = {str(k).lower(): v for k, v in (patch_files or {}).items()}
    patch_dir = patch_dir or _env("CMS_PATCH_DIR")
    schedule_info = _parse_schedule(schedule)
    wanted = {str(h).lower() for h in hostnames}

    with dsm() as c:
        if not c.has("SYNO.CMS.DS") or not c.has("SYNO.CMS.Task"):
            raise RuntimeError("Central Management System ist auf dieser NAS nicht installiert oder nicht erreichbar")
        devices = [d for d in _cms_devices(c) if (d["hostname"] or "").lower() in wanted]
        missing = wanted - {(d["hostname"] or "").lower() for d in devices}

        # neueste Version pro Gerät beim Synology-Server (wie cms_updates)
        targets, seen = [], set()
        for dev in devices:
            key = (dev["unique"], dev["dsm_version"])
            if dev["unique"] and dev["dsm_version"] and key not in seen:
                seen.add(key)
                targets.append({"dsm_version": dev["dsm_version"], "unique": dev["unique"]})
        infos = c.call("SYNO.Core.Upgrade.Group", "info", version=1, _timeout=300,
                       target=targets).get("result", []) if targets else []

        # Patch-Datei pro Gerät bestimmen und auf der CMS-NAS prüfen
        wanted_paths, per_dev = [], {}
        for dev in devices:
            explicit = patch_files.get((dev["hostname"] or "").lower())
            if explicit:
                paths = [explicit]
            else:
                info = next((i for i in infos if _model_key(i.get("unique")) == _model_key(dev["unique"])
                             and i.get("current_version") == dev["dsm_version"]), None)
                latest = _parse_dsm((info or {}).get("latest_version"))
                paths = _patch_candidates(dev, latest["build"], patch_dir) if (latest and patch_dir) else []
            per_dev[dev["id"]] = paths
            wanted_paths += paths
        stats = _patch_info(c, list(dict.fromkeys(wanted_paths)))

        plan, abgelehnt = [], []
        for dev in devices:
            reason, patch = None, None
            cur = _parse_dsm(dev["dsm_version"])
            for p in per_dev[dev["id"]]:
                st = stats.get(p) or {}
                if st.get("success") and st.get("exist", True):
                    patch = st
                    break
            if dev["status_code"] != 2:
                reason = f"nicht online ({dev['status']})"
            elif dev.get("self"):
                reason = "ist die CMS-NAS selbst, bitte direkt in deren DSM aktualisieren"
            elif not patch:
                reason = ("keine passende .pat-Datei auf der CMS-NAS gefunden"
                          + (f" (gesucht: {', '.join(per_dev[dev['id']])})" if per_dev[dev["id"]]
                             else " (patch_dir/CMS_PATCH_DIR oder patch_files angeben)"))
            else:
                new = _parse_dsm(patch.get("version"))
                if _model_key(patch.get("model")) != _model_key(dev["unique"]):
                    reason = f"Patch ist für ein anderes Modell ({patch.get('model')})"
                elif not cur or not new or new["build"] <= cur["build"]:
                    reason = f"Patch {patch.get('version')} ist nicht neuer als {dev['dsm_version']}"
                elif new["major"] != cur["major"] and not allow_major:
                    reason = (f"Major-Upgrade {dev['dsm_version']} -> {patch.get('version')} "
                              f"nur mit allow_major=true")
            if reason:
                abgelehnt.append({"hostname": dev["hostname"], "grund": reason})
                continue
            plan.append({
                "id": dev["id"], "hostname": dev["hostname"], "host": dev["host"],
                "http_port": dev["http_port"] or 0, "dsm_version": dev["dsm_version"], "self": False,
                "file": patch["path"], "model": dev["modell"], "updated_version": f"DSM {patch.get('version')}",
            })
        for h in sorted(missing):
            abgelehnt.append({"hostname": h, "grund": "nicht im CMS gefunden"})

        result = {
            "geplant": [{"hostname": p["hostname"], "von": p["dsm_version"], "auf": p["updated_version"],
                         "datei": p["file"]} for p in plan],
            "abgelehnt": abgelehnt,
            "zeitpunkt": schedule or "sofort",
            "hinweis": "Die Geräte starten beim Update neu und sind einige Minuten nicht erreichbar.",
        }
        if not confirm:
            result["vorschau"] = True
            result["ausfuehren"] = "Mit confirm=true wird die CMS-Aufgabe angelegt."
            return result
        if not _write_allowed():
            raise RuntimeError("Schreibende Aktionen sind deaktiviert (MCP_ALLOW_WRITE=true im Container setzen)")
        if not plan:
            raise RuntimeError("Kein Gerät kann aktualisiert werden, es wurde keine Aufgabe angelegt")

        params = {"action": "dsm_update", "description": "DSM-Aktualisierung (synology-mcp)",
                  "target_groups": [], "target_servers": [p["id"] for p in plan],
                  "additional_info": {"dsm_update_params": plan}}
        if schedule_info:
            params["schedule_info"] = schedule_info
        created = c.call("SYNO.CMS.Task", "create", version=1, **params)
        result["aufgabe"] = created
        result["vorschau"] = False
        result["kontrolle"] = "Fortschritt mit cms_tasks (task_uuid) abfragen."
        return result


def cms_tasks(task_uuid: str = None) -> dict:
    """CMS-Aufgaben (z.B. DSM-Aktualisierung) auflisten oder Fortschritt pro Gerät einer Aufgabe zeigen."""
    with dsm() as c:
        if not c.has("SYNO.CMS.Task"):
            return {"hinweis": "Central Management System ist auf dieser NAS nicht installiert oder nicht erreichbar"}
        if not task_uuid:
            d = c.call("SYNO.CMS.Task", "list", version=1)
            return {"aufgaben": [{"task_uuid": t.get("task_uuid"), "name": t.get("task_name"),
                                  "aktion": t.get("action_type"), "status": t.get("task_status"),
                                  "erstellt": _epoch(t.get("create_time")), "fertig": _epoch(t.get("done_time")),
                                  "ziele": t.get("target_total"), "erledigt": t.get("target_done"),
                                  "in_arbeit": t.get("target_processing")} for t in d.get("tasks", [])]}
        d = c.call("SYNO.CMS.Task.Target", "list", version=1, get_task=True, task_uuid=task_uuid, offset=0, limit=200)
    ziele = []
    for t in d.get("task_targets", []):
        extra = t.get("additional_info") or {}
        if isinstance(extra, str):
            try:
                extra = json.loads(extra)
            except ValueError:
                extra = {}
        params, prog = extra.get("dsm_update_params") or {}, extra.get("dsm_update_progress") or {}
        ziele.append({"hostname": t.get("client_hostname"), "status": t.get("task_target_status"),
                      "fehler": None if t.get("task_target_fail_reason") in (None, "none") else t.get("task_target_fail_reason"),
                      "schritt": prog.get("step"), "prozent": prog.get("percent") or None,
                      "von": params.get("dsm_version"), "auf": params.get("updated_version"),
                      "fertig": _epoch(t.get("done_time"))})
    task = d.get("task") or {}
    return {"aufgabe": {"name": task.get("task_name"), "status": task.get("task_status"),
                        "erstellt": _epoch(task.get("create_time"))}, "ziele": ziele}


def packages() -> list[dict]:
    """Installierte Pakete mit Version und Status."""
    with dsm() as c:
        d = c.call("SYNO.Core.Package", "list", additional=["status", "installed_info"])
        out = [{"id": p.get("id"), "name": p.get("name"), "version": p.get("version"),
                "status": (p.get("additional") or {}).get("status")} for p in d.get("packages", [])]
        return sorted(out, key=lambda p: (p["name"] or "").lower())


def shares() -> list[dict]:
    """Freigegebene Ordner mit Volume, Beschreibung, Verschlüsselung und Kontingent."""
    with dsm() as c:
        d = c.call("SYNO.Core.Share", "list",
                   additional=["hidden", "encryption", "share_quota", "recyclebin", "vol_path"])
        out = []
        for s in d.get("shares", []):
            a = s.get("additional") or {}
            out.append({"name": s.get("name"), "volume": s.get("vol_path") or a.get("vol_path"),
                        "beschreibung": s.get("desc") or None, "verschluesselt": a.get("encryption"),
                        "versteckt": a.get("hidden"), "papierkorb": a.get("enable_recycle_bin", a.get("recyclebin")),
                        "kontingent_mb": a.get("share_quota") or a.get("quota_value"),
                        "belegt_mb": a.get("share_quota_used")})
        return out


def connections() -> list[dict]:
    """Aktuell angemeldete Benutzer und Verbindungen (DSM, SMB, Drive usw.)."""
    with dsm() as c:
        d = c.call("SYNO.Core.CurrentConnection", "get")
        items = d.get("items", d if isinstance(d, list) else [])
        return [{"user": i.get("who"), "von": i.get("from"), "typ": i.get("type"),
                 "beschreibung": i.get("descr"), "seit": i.get("time")} for i in items]


def logs(limit: int = 50, keyword: str = None) -> list[dict]:
    """Einträge aus dem Log Center (System-Log der NAS), neueste zuerst."""
    with dsm() as c:
        limit = max(1, min(int(limit), 500))
        d = c.call("SYNO.Core.SyslogClient.Log", "list", start=0, limit=limit, keyword=keyword or None)
        return [{"zeit": i.get("time"), "stufe": i.get("level"), "user": i.get("who"),
                 "meldung": i.get("descr"), "programm": i.get("logtype") or i.get("program")}
                for i in d.get("items", [])][:limit]


def _security(c: DSMClient) -> dict:
    d = c.call("SYNO.Core.SecurityScan.Status", "system_get")
    items = d.get("items") or {}
    risky = {k: v.get("failSeverity") for k, v in items.items()
             if isinstance(v, dict) and not _ok(v.get("failSeverity"))}
    out = {"gesamtstatus": d.get("sysStatus"), "letzter_scan": _epoch(d.get("lastScanTime")),
           "laeuft": d.get("sysProgress") not in (None, 100) if d.get("sysProgress") is not None else None,
           "kategorien_mit_befund": risky}
    try:
        rules = c.call("SYNO.Core.SecurityScan.Status", "rule_get", items="ALL").get("items") or {}
        out["fehlgeschlagene_regeln"] = sorted(
            ({"regel": r.get("strId") or k, "kategorie": r.get("category"), "schwere": r.get("severity")}
             for k, r in rules.items() if isinstance(r, dict) and r.get("status") == "fail"),
            key=lambda r: (r["kategorie"] or "", r["regel"]))
    except Exception as e:
        out["fehlgeschlagene_regeln"] = {"fehler": str(e)}
    return out


def security_advisor() -> dict:
    """Ergebnis des letzten Security-Advisor-Scans (startet keinen neuen Scan)."""
    with dsm() as c:
        return _security(c)


def drive_status() -> dict:
    """Synology Drive: Verbindungsübersicht und Teamordner (ohne Dateinamen oder Inhalte)."""
    with dsm() as c:
        out: dict[str, Any] = {}
        if not c.has("SYNO.SynologyDrive.Connection"):
            return {"hinweis": "Synology Drive Server ist nicht installiert oder die API ist nicht erreichbar"}
        for key, api, method in (("verbindungen", "SYNO.SynologyDrive.Connection", "summary"),
                                 ("teamordner", "SYNO.SynologyDrive.TeamFolders", "list")):
            try:
                out[key] = c.call(api, method)
            except Exception as e:
                out[key] = {"fehler": str(e)}
        return out


def health_report() -> dict:
    """Zusammenfassender Zustandsbericht mit Auffälligkeiten (System, Speicher, Backups, Updates, Security)."""
    vol_warn = _float_env("MCP_VOLUME_WARN_PERCENT", 85)
    temp_warn = _float_env("MCP_DISK_TEMP_WARN", 55)
    life_warn = _float_env("MCP_DISK_LIFE_WARN_PERCENT", 20)
    report: dict[str, Any] = {"erstellt": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}
    issues: list[str] = []
    with dsm() as c:
        for key, func in (("system", _system_info), ("auslastung", _utilization), ("speicher", _storage),
                          ("backups", _backup_tasks), ("updates", _updates), ("security_advisor", _security)):
            try:
                report[key] = func(c)
            except Exception as e:
                report[key] = {"fehler": str(e)}
                issues.append(f"{key}: konnte nicht gelesen werden ({e})")

    sysi = report.get("system") or {}
    if sysi.get("temperatur_warnung"):
        issues.append(f"System-Temperatur-Warnung ({sysi.get('temperatur_c')} °C)")

    st = report.get("speicher") or {}
    for p in st.get("pools", []):
        if not _ok(p.get("status")):
            issues.append(f"Speicherpool {p.get('id')}: Status {p.get('status')}")
    for v in st.get("volumes", []):
        if not _ok(v.get("status")):
            issues.append(f"Volume {v.get('pfad') or v.get('id')}: Status {v.get('status')}")
        if (v.get("belegt_prozent") or 0) >= vol_warn:
            issues.append(f"Volume {v.get('pfad') or v.get('id')}: {v.get('belegt_prozent')} % belegt (Grenze {vol_warn:g} %)")
    for d in st.get("disks", []):
        name = d.get("name") or d.get("id")
        if not _ok(d.get("status")):
            issues.append(f"Disk {name}: Status {d.get('status')}")
        if not _ok(d.get("smart_status")):
            issues.append(f"Disk {name}: SMART {d.get('smart_status')}")
        if (_num(d.get("temperatur_c")) or 0) >= temp_warn:
            issues.append(f"Disk {name}: {d.get('temperatur_c')} °C (Grenze {temp_warn:g} °C)")
        unc = _num(d.get("unc"))
        if unc and unc > 0:
            issues.append(f"Disk {name}: {unc:g} unkorrigierbare Sektorfehler (UNC) - Disk beobachten, Ersatz bereithalten")
        if d.get("bad_sector_grenze_ueberschritten"):
            issues.append(f"Disk {name}: Grenze für fehlerhafte Sektoren überschritten")
        if d.get("restlebensdauer_unter_grenze"):
            issues.append(f"Disk {name}: Restlebensdauer unter der DSM-Grenze")
        life = _num(d.get("restlebensdauer_prozent"))
        if life is not None and life <= life_warn:
            issues.append(f"Disk {name}: Restlebensdauer {life:g} %")

    backups = report.get("backups")
    if isinstance(backups, list):
        for b in backups:
            res = str(b.get("letztes_ergebnis") or "").lower()
            if res and res not in ("done", "success", "backingup", "none"):
                issues.append(f"Backup '{b.get('name')}': letztes Ergebnis {b.get('letztes_ergebnis')}")
            if b.get("fehler_status"):
                issues.append(f"Backup '{b.get('name')}': Status nicht lesbar")

    if (report.get("updates") or {}).get("update_verfuegbar"):
        issues.append(f"DSM-Update verfügbar: {report['updates'].get('version')}")

    sec = report.get("security_advisor") or {}
    rules = sec.get("fehlgeschlagene_regeln")
    if isinstance(rules, list) and rules:
        issues.append("Security Advisor: " + ", ".join(f"{r['regel']} ({r['schwere']})" for r in rules))
    elif sec.get("kategorien_mit_befund"):
        issues.append(f"Security Advisor: Befunde in {', '.join(sec['kategorien_mit_befund'])}")

    report["auffaelligkeiten"] = issues
    report["zustand"] = "ok" if not issues else "pruefen"
    return report


def api_list(filter: str = None) -> list[dict]:
    """Verfügbare DSM-APIs mit Versionen (zum Finden von APIs für api_query)."""
    with dsm() as c:
        f = (filter or "").lower()
        return [{"api": k, "min": v.get("minVersion"), "max": v.get("maxVersion")}
                for k, v in sorted(c.api_info().items()) if f in k.lower()]


# Generischer Lesezugriff: nur lesende Methoden, keine APIs mit Zugangsdaten oder Dateiinhalten.
_READ_METHODS = {"list", "get", "info", "getinfo", "load_info", "status", "summary", "get_status",
                 "system_get", "rule_get", "list_active", "query", "load", "get_sys_info"}
_BLOCKED_API = re.compile(
    r"^SYNO\.API\.Auth|passw|passwd|secret|token|otp|key|cert|credential|encrypt|"
    r"^SYNO\.FileStation|^SYNO\.SynologyDrive\.(Files|Node)|^SYNO\.Foto|^SYNO\.Photo|"
    r"^SYNO\.Office|^SYNO\.Note|^SYNO\.Mail|^SYNO\.Chat|^SYNO\.Contacts|^SYNO\.Cal\b|^SYNO\.Calendar|"
    # Lesend, aber mit Konfigurationsdaten, die Zugangsdaten oder Zugriffsrechte enthalten können:
    # Aufgabenplaner (Skripte), VPN/PPPoE, DDNS-Konten, Backup-Ziele, Benutzer, Freigabe-Rechte,
    # Sicherheitseinstellungen (Firewall, Auto-Block), Syslog-Client
    r"^SYNO\.Core\.TaskScheduler|^SYNO\.Core\.Network\.(VPN|PPPoE)|^SYNO\.Core\.DDNS|^SYNO\.Backup\.Target|"
    r"^SYNO\.Core\.User|^SYNO\.Core\.Share\.Permission|^SYNO\.Core\.Security\.|^SYNO\.Core\.SyslogClient(?!\.Log\b)",
    re.IGNORECASE,
)


def _check_query_allowed(api: str, method: str) -> None:
    if method not in _READ_METHODS:
        raise RuntimeError(f"Methode '{method}' ist nicht erlaubt, nur lesende Methoden: {', '.join(sorted(_READ_METHODS))}")
    if _BLOCKED_API.search(api):
        raise RuntimeError(f"API '{api}' ist gesperrt (Zugangsdaten, Schlüssel oder Benutzerdaten)")


def api_query(api: str, method: str, params: dict = None, version: str = "max") -> Any:
    """Lesender Aufruf einer beliebigen DSM-API (Methoden-Allowlist, Blocklist für sensible APIs)."""
    _check_query_allowed(api, method)
    params = dict(params or {})
    for k in list(params):
        if k.startswith("_") or k in ("api", "method", "version"):
            params.pop(k)
    with dsm() as c:
        return c.call(api, method, version=version, **params)


TOOL_FUNCS = {
    "get_version": get_version,
    "tls_check": tls_check,
    "system_info": system_info,
    "utilization": utilization,
    "storage": storage,
    "backup_tasks": backup_tasks,
    "updates": updates,
    "cms_updates": cms_updates,
    "cms_dsm_update": cms_dsm_update,
    "cms_tasks": cms_tasks,
    "packages": packages,
    "shares": shares,
    "connections": connections,
    "logs": logs,
    "security_advisor": security_advisor,
    "drive_status": drive_status,
    "health_report": health_report,
    "api_list": api_list,
    "api_query": api_query,
}


# ---------------------------------------------------------------------------
# MCP-Server
# ---------------------------------------------------------------------------

server = Server("synology-mcp")

_EMPTY = {"type": "object", "properties": {}}


@server.list_tools()
async def list_tools():
    return [
        Tool(name="get_version", description="Version des laufenden Synology-MCP-Servers abfragen (Redeploy-Kontrolle).", inputSchema=_EMPTY),
        Tool(name="tls_check", description="Diagnose: welches TLS-Zertifikat die NAS ausliefert (Subject, Aussteller, Namen, Gültigkeit, SHA-256) und ob die Prüfung klappt. Sendet keine Zugangsdaten.", inputSchema=_EMPTY),
        Tool(name="system_info", description="NAS: Modell, DSM-Version, CPU, RAM, Temperatur, Uptime (auch als Verbindungstest).", inputSchema=_EMPTY),
        Tool(name="utilization", description="Aktuelle Auslastung: CPU, Load, RAM, Swap, Netzwerk und Disk-I/O.", inputSchema=_EMPTY),
        Tool(name="storage", description="Speicherpools, Volumes mit Belegung und Disks mit Status, SMART, Temperatur und Restlebensdauer.", inputSchema=_EMPTY),
        Tool(name="backup_tasks", description="Hyper-Backup-Aufgaben mit letztem Ergebnis sowie letzter und nächster Ausführung.", inputSchema=_EMPTY),
        Tool(name="updates", description="Prüft, ob ein DSM-Update verfügbar ist. Installiert nichts.", inputSchema=_EMPTY),
        Tool(name="cms_updates",
             description="DSM-Updates aller Geräte im Central Management System (CMS): Hostname, Modell, Status (online/offline), installierte und neueste DSM-Version. Fragt nur ab, lädt und installiert nichts.",
             inputSchema={"type": "object", "properties": {
                 "nur_verfuegbar": {"type": "boolean", "default": False, "description": "Nur Geräte mit verfügbarem Update auflisten"},
             }}),
        Tool(name="cms_dsm_update",
             description="DSM-Update über das Central Management System an ausgewählte Geräte verteilen (wie CMS > Aufgabe > DSM-Aktualisierung). Die Geräte starten dabei neu. Nutzt .pat-Dateien, die bereits auf der CMS-NAS liegen (patch_files pro Gerät oder patch_dir/CMS_PATCH_DIR mit DSM_<Modell>_<Build>.pat). Lehnt offline-Geräte, die CMS-NAS selbst, nicht neuere Builds und Major-Upgrades (ausser allow_major=true) ab. Ohne confirm=true nur Vorschau; ausgeführt nur mit MCP_ALLOW_WRITE=true.",
             inputSchema={"type": "object", "properties": {
                 "hostnames": {"type": "array", "items": {"type": "string"}, "description": "Hostnamen wie in cms_updates"},
                 "patch_files": {"type": "object", "description": "Optional: Hostname -> Pfad der .pat-Datei auf der CMS-NAS"},
                 "patch_dir": {"type": "string", "description": "Optional: Ordner mit den .pat-Dateien auf der CMS-NAS (sonst CMS_PATCH_DIR)"},
                 "schedule": {"type": "string", "description": "Optional: 'YYYY-MM-DD HH:MM' in der Zeitzone der CMS-NAS, leer = sofort"},
                 "allow_major": {"type": "boolean", "default": False, "description": "Major-Upgrade (z.B. DSM 6 -> 7) erlauben"},
                 "confirm": {"type": "boolean", "default": False, "description": "true = CMS-Aufgabe wirklich anlegen"},
             }, "required": ["hostnames"]}),
        Tool(name="cms_tasks",
             description="CMS-Aufgaben (z.B. DSM-Aktualisierung) auflisten; mit task_uuid Status, Schritt und Fehler pro Gerät.",
             inputSchema={"type": "object", "properties": {
                 "task_uuid": {"type": "string", "description": "Optional: UUID einer Aufgabe aus der Liste"},
             }}),
        Tool(name="packages", description="Installierte Pakete mit Version und Status.", inputSchema=_EMPTY),
        Tool(name="shares", description="Freigegebene Ordner mit Volume, Verschlüsselung, Papierkorb und Kontingent.", inputSchema=_EMPTY),
        Tool(name="connections", description="Aktuell angemeldete Benutzer und Verbindungen.", inputSchema=_EMPTY),
        Tool(name="logs", description="Einträge aus dem Log Center der NAS, neueste zuerst.",
             inputSchema={"type": "object", "properties": {
                 "limit": {"type": "integer", "default": 50},
                 "keyword": {"type": "string", "description": "Suchbegriff"},
             }}),
        Tool(name="security_advisor", description="Ergebnis des letzten Security-Advisor-Scans. Startet keinen neuen Scan.", inputSchema=_EMPTY),
        Tool(name="drive_status", description="Synology Drive: Verbindungsübersicht und Teamordner, ohne Dateinamen oder Inhalte.", inputSchema=_EMPTY),
        Tool(name="health_report",
             description="Zusammenfassender Zustandsbericht der NAS mit Liste der Auffälligkeiten (Temperatur, Pools, Volumes, Disks/SMART, Backups, Updates, Security Advisor).",
             inputSchema=_EMPTY),
        Tool(name="api_list", description="Verfügbare DSM-APIs mit Versionen, optional gefiltert (Hilfe für api_query).",
             inputSchema={"type": "object", "properties": {"filter": {"type": "string", "description": "Teil des API-Namens"}}}),
        Tool(name="api_query",
             description="Lesender Aufruf einer beliebigen DSM-API für Fälle, die kein eigenes Tool haben. Nur lesende Methoden (list, get, info, load, load_info, status, summary usw.), APIs mit Zugangsdaten, Schlüsseln oder Benutzerdateien sind gesperrt.",
             inputSchema={"type": "object", "properties": {
                 "api": {"type": "string", "description": "z.B. SYNO.Core.Share"},
                 "method": {"type": "string", "description": "z.B. list"},
                 "params": {"type": "object", "description": "Zusätzliche Parameter"},
                 "version": {"type": "string", "default": "max", "description": "max, min oder Versionsnummer"},
             }, "required": ["api", "method"]}),
    ]


def _format_error(e: Exception) -> str:
    return f"Fehler: {e}"


@server.call_tool()
async def call_tool(name, arguments):
    func = TOOL_FUNCS.get(name)
    if not func:
        return [TextContent(type="text", text=f"Unbekanntes Tool: {name}")]
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, lambda: func(**(arguments or {})))
        text = result if isinstance(result, str) else json.dumps(result, ensure_ascii=False, indent=2, default=str)
        return [TextContent(type="text", text=text)]
    except Exception as e:
        return [TextContent(type="text", text=_format_error(e))]


# ---------------------------------------------------------------------------
# Cloud/HTTP-Betrieb (identisch zu esxi-mcp): statisches Bearer-Token schützt /mcp
# ---------------------------------------------------------------------------

MCP_AUTH_TOKEN = os.environ.get("MCP_AUTH_TOKEN", "")
MCP_AUTH_TOKEN_MIN_LENGTH = 32


class _StreamableHTTPASGIApp:
    def __init__(self, session_manager):
        self.session_manager = session_manager

    async def __call__(self, scope, receive, send):
        await self.session_manager.handle_request(scope, receive, send)


class BearerAuthMiddleware:
    """Prüft 'Authorization: Bearer <token>' (zeitkonstanter Vergleich)."""

    def __init__(self, app, token: str):
        self.app = app
        self.token = token

    async def __call__(self, scope, receive, send):
        import hmac
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers", []))
        auth_header = headers.get(b"authorization", b"").decode("latin-1")
        if not self.token or not hmac.compare_digest(auth_header.encode(), f"Bearer {self.token}".encode()):
            from starlette.responses import JSONResponse
            await JSONResponse({"error": "unauthorized"}, status_code=401)(scope, receive, send)
            return
        await self.app(scope, receive, send)


def with_healthz(app):
    """GET /healthz ohne Auth für den Docker-Healthcheck. Liefert nur {"status": "ok"},
    prüft nur den Prozess, nicht die NAS."""
    from starlette.responses import JSONResponse

    async def router(scope, receive, send):
        if scope["type"] == "http" and scope["path"] == "/healthz" and scope["method"] in ("GET", "HEAD"):
            await JSONResponse({"status": "ok"})(scope, receive, send)
            return
        await app(scope, receive, send)

    return router


def build_http_app(token: str):
    from starlette.applications import Starlette
    from starlette.routing import Route
    from starlette.middleware.cors import CORSMiddleware
    from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
    from mcp.server.transport_security import TransportSecuritySettings

    session_manager = StreamableHTTPSessionManager(
        app=server,
        json_response=True,
        security_settings=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )
    app = Starlette(
        routes=[Route("/mcp", endpoint=_StreamableHTTPASGIApp(session_manager))],
        lifespan=lambda app: session_manager.run(),
    )
    return CORSMiddleware(
        with_healthz(BearerAuthMiddleware(app, token)),
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["mcp-session-id"],
    )


async def run_http_server():
    import uvicorn

    host = os.environ.get("MCP_HOST", "0.0.0.0")
    port = int(os.environ.get("MCP_PORT", "8000"))
    srv = uvicorn.Server(uvicorn.Config(build_http_app(MCP_AUTH_TOKEN), host=host, port=port, log_level="info"))
    print(f"Synology MCP HTTP server {__version__} running on {host}:{port}", flush=True)
    await srv.serve()


def main():
    if len(MCP_AUTH_TOKEN) < MCP_AUTH_TOKEN_MIN_LENGTH:
        raise RuntimeError(
            f"MCP_AUTH_TOKEN fehlt oder ist zu kurz (mind. {MCP_AUTH_TOKEN_MIN_LENGTH} Zeichen) - aus Sicherheitsgründen kein Start."
        )
    asyncio.run(run_http_server())


if __name__ == "__main__":
    main()
