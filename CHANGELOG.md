# Changelog

## 0.4

- Neues Tool `cms_dsm_update`: DSM-Update über das Central Management System an ausgewählte Geräte verteilen (CMS-Aufgabe `dsm_update`, wie im Webinterface). Nutzt `.pat`-Dateien auf der CMS-NAS (`patch_dir`/`CMS_PATCH_DIR` oder `patch_files`), prüft sie vorher über das CMS, lehnt offline-Geräte, die CMS-NAS selbst, falsches Modell, nicht neuere Builds und Major-Upgrades (ohne `allow_major`) ab, optional geplant (`schedule`). Ohne `confirm=true` nur Vorschau, ausgeführt nur mit `MCP_ALLOW_WRITE=true`.
- Neues Tool `cms_tasks`: CMS-Aufgaben auflisten und Fortschritt/Fehler pro Gerät.
- `cms_updates` liest zusätzlich Host, Port und Build der Geräte (intern für `cms_dsm_update`).

## 0.3

- Zertifikats-Pinning (`DSM_TLS_FINGERPRINT`) greift jetzt im TLS-Handshake statt erst nach der Antwort: Das DSM-Zertifikat wird einmal ohne Zugangsdaten geholt, mit dem Fingerprint verglichen und als einzige Vertrauensbasis in den SSL-Kontext geladen. Vorher wurde mit `verify=False` verbunden und das Zertifikat erst nach dem Response verglichen, der Login mit Passwort konnte so auf einer neuen Verbindung an eine falsche Gegenstelle gehen. Mit `DSM_TLS_SERVERNAME` wird zusätzlich der Name geprüft. Der separate Preflight-Request entfällt.
- `api_query`: Sperre um lesende APIs erweitert, deren Konfiguration Zugangsdaten oder Zugriffsrechte enthalten kann (`SYNO.Core.TaskScheduler`, `SYNO.Core.Network.VPN`/`PPPoE`, `SYNO.Core.DDNS`, `SYNO.Backup.Target`, `SYNO.Core.User`, `SYNO.Core.Share.Permission`, `SYNO.Core.Security.*`, `SYNO.Core.SyslogClient` ausser `.Log`).
- `MCP_AUTH_TOKEN` muss mindestens 32 Zeichen lang sein (vorher 24).
- Compose: Host-Port standardmässig nur auf `127.0.0.1` gemappt (`MCP_BIND_ADDR`), vorher `0.0.0.0`.
- Abhängigkeiten exakt gepinnt; `cryptography` nur für die Tests.
- Tests für Pinning gegen lokalen HTTPS-Server (korrekter Pin, falscher Pin, gewechseltes Zertifikat, Hostname-Prüfung) und für die erweiterte Sperrliste.

## 0.2

- Neues Tool `cms_updates`: DSM-Updates aller Geräte im Central Management System (Hostname, Modell, Status, installierte und neueste Version), optional nur Geräte mit verfügbarem Update. Statuscodes des CMS werden als Text ausgegeben (z.B. 10 = offline).
- `updates`: Abfrage wie die Systemsteuerung (SYNO.Core.Upgrade.Server.check Version 3 mit deren Parametern), vorher Fehler 119 unter DSM 7.4.
- Längerer Timeout für Update-Abfragen beim Synology-Server.

## 0.1

- Erste Version, nur lesend: System, Auslastung, Speicher (Pools, Volumes, Disks mit SMART), Hyper Backup, Updates, Pakete, Freigaben, Verbindungen, Log Center, Security Advisor, Synology Drive.
- `health_report` fasst alles zusammen und listet Auffälligkeiten mit einstellbaren Schwellwerten.
- `api_query` für lesende Aufrufe ohne eigenes Tool, mit Methoden-Allowlist und Sperre sensibler APIs.
- Pro Tool-Aufruf eine DSM-Session mit Logout danach.
- `DSM_TLS_SERVERNAME`: Verbindung per interner IP, Zertifikat wird trotzdem gegen den externen Namen geprüft.
- `tls_check` zur Zertifikats-Diagnose, `DSM_TLS_FINGERPRINT` für Zertifikats-Pinning.
- Auswertung gegen echte NAS korrigiert: Load richtig skaliert, Pool-Wert als zugewiesener Anteil, UNC-Sektorfehler werden gemeldet, Security Advisor listet die fehlgeschlagenen Regeln.
