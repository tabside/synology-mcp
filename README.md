# Synology MCP Server

MCP-Server für eine Synology-NAS mit DSM 7, über die DSM Web API. Zustand, Auslastung, Speicherpools, Volumes, Disks (SMART, Temperatur, Restlebensdauer), Hyper-Backup-Aufgaben, Updates, Pakete, freigegebene Ordner, Verbindungen, Log Center, Security Advisor und Synology Drive lesen, dazu ein zusammenfassender Zustandsbericht. Gleicher Aufbau wie esxi-mcp und pbs-mcp: läuft ausschliesslich als Docker-Container (Streamable HTTP) hinter einem Reverse-Proxy, Schutz per statischem Bearer-Token (`MCP_AUTH_TOKEN`), Image per GitHub Actions nach ghcr.io.

Der Server ist **nur lesend**:

- es gibt keine schreibenden Tools (kein Neustart, keine Paket-, Freigabe- oder Backup-Aktionen)
- `updates` prüft nur, ob ein Update verfügbar ist, und installiert nichts
- `cms_updates` liest die Geräteliste des CMS und fragt beim Synology-Updateserver die neueste Version pro Modell ab, wie die Seite CMS > Update. Es wird nichts heruntergeladen oder verteilt. Ob ein Update als kritisch eingestuft ist, liefert diese Abfrage nicht
- `security_advisor` liest das Ergebnis des letzten Scans und startet keinen neuen
- `api_query` erlaubt nur lesende Methoden und sperrt APIs mit Zugangsdaten, Schlüsseln, Zertifikaten und Benutzerdateien (File Station, Drive-Dateien, Photos, Office, Mail usw.) sowie lesende APIs, deren Konfiguration Zugangsdaten oder Zugriffsrechte enthalten kann (Aufgabenplaner, VPN/PPPoE, DDNS, Backup-Ziele, Benutzer, Freigabe-Rechte, Firewall/Auto-Block, Syslog-Client)
- `drive_status` liefert nur Verbindungs- und Teamordner-Übersichten, keine Dateinamen oder Inhalte
- jeder Tool-Aufruf meldet sich an der NAS an und danach wieder ab, es bleiben keine Sessions offen

## Tools

| Tool | Beschreibung |
|------|--------------|
| `get_version` | Version des laufenden MCP-Servers (Redeploy-Kontrolle) |
| `tls_check` | Diagnose: welches Zertifikat die NAS ausliefert (Aussteller, Namen, Gültigkeit, SHA-256) und ob die Prüfung klappt, ohne Zugangsdaten |
| `system_info` | Modell, DSM-Version, CPU, RAM, Temperatur, Uptime (auch Verbindungstest) |
| `utilization` | CPU, Load, RAM, Swap, Netzwerk, Disk-I/O |
| `storage` | Speicherpools (zugewiesener Anteil), Volumes mit Belegung, Disks mit Status, SMART, UNC-Fehler, Temperatur, Restlebensdauer |
| `backup_tasks` | Hyper-Backup-Aufgaben mit letztem Ergebnis, letzter und nächster Ausführung |
| `updates` | Ist ein DSM-Update verfügbar? |
| `cms_updates` | DSM-Updates aller Geräte im Central Management System: Hostname, Modell, Status, installierte und neueste Version (optional nur Geräte mit Update) |
| `packages` | Installierte Pakete mit Version und Status |
| `shares` | Freigegebene Ordner mit Volume, Verschlüsselung, Papierkorb, Kontingent |
| `connections` | Aktuell angemeldete Benutzer und Verbindungen |
| `logs` | Log Center, neueste zuerst, optional mit Suchbegriff |
| `security_advisor` | Ergebnis des letzten Security-Advisor-Scans |
| `drive_status` | Synology Drive: Verbindungsübersicht und Teamordner |
| `health_report` | Zustandsbericht aus allem oben mit Liste der Auffälligkeiten |
| `api_list` | Verfügbare DSM-APIs mit Versionen |
| `api_query` | Lesender Aufruf einer beliebigen DSM-API für Fälle ohne eigenes Tool |

`health_report` meldet als Auffälligkeit: Temperatur-Warnung des Systems, Pools/Volumes/Disks mit Status ungleich `normal`, SMART ungleich `normal`, unkorrigierbare Sektorfehler (UNC), Volumes ab `MCP_VOLUME_WARN_PERCENT`, Disks ab `MCP_DISK_TEMP_WARN` °C, überschrittene Grenze für fehlerhafte Sektoren, Restlebensdauer unter der DSM-Grenze oder unter `MCP_DISK_LIFE_WARN_PERCENT`, Backups mit fehlgeschlagenem letzten Ergebnis, verfügbare Updates und Befunde des Security Advisors. Teile, die nicht gelesen werden können, erscheinen ebenfalls als Auffälligkeit.

## Umgebungsvariablen

| Variable | Pflicht | Standard | Beschreibung |
|---|---|---|---|
| `DSM_HOST` | ja | - | z.B. `nas.example.com` |
| `DSM_PORT` | nein | `5001` | HTTPS-Port von DSM |
| `DSM_HTTPS` | nein | `true` | `false` nur im internen Netz |
| `DSM_USER` | ja | - | eigener User nur für den MCP |
| `DSM_PASSWORD` | ja | - | |
| `DSM_VERIFY_SSL` | nein | `true` | `true`, `false` oder Pfad zu einer CA-Datei |
| `DSM_TLS_SERVERNAME` | nein | - | Name, auf den das DSM-Zertifikat ausgestellt ist, wenn `DSM_HOST` eine interne IP ist. Das Zertifikat wird dann gegen diesen Namen geprüft, statt die Prüfung abzuschalten |
| `DSM_TLS_FINGERPRINT` | nein | - | SHA-256 des DSM-Zertifikats (mit oder ohne Doppelpunkte, siehe `tls_check`). Ersetzt die CA-Prüfung, z.B. bei selbstsigniertem Zertifikat im LAN. Das Zertifikat wird einmal per reinem TLS-Handshake (ohne Zugangsdaten) geholt, mit dem Fingerprint verglichen und dann als einzige Vertrauensbasis geladen. Jede Verbindung, auch der Login, scheitert bei einem anderen Zertifikat bereits im Handshake, bevor Daten gesendet werden. Ist zusätzlich `DSM_TLS_SERVERNAME` gesetzt, wird auch der Name im Zertifikat geprüft |
| `MCP_AUTH_TOKEN` | ja | - | Statisches Bearer-Token (mind. 32 Zeichen), ohne startet der Server nicht |
| `MCP_VOLUME_WARN_PERCENT` | nein | `85` | Belegung, ab der ein Volume gemeldet wird |
| `MCP_DISK_TEMP_WARN` | nein | `55` | Disk-Temperatur in °C, ab der gemeldet wird |
| `MCP_DISK_LIFE_WARN_PERCENT` | nein | `20` | Restlebensdauer (SSD), ab der gemeldet wird |
| `MCP_HOST` / `MCP_PORT` | nein | `0.0.0.0` / `8000` | Bind im Container |
| `MCP_BIND_ADDR` / `MCP_HOST_PORT` | nein | `127.0.0.1` / `8432` | Port-Mapping auf dem Docker-Host. Standard nur localhost; läuft der Reverse-Proxy auf einem anderen Host, die LAN-IP des Docker-Hosts setzen |

## 1. User auf der NAS anlegen

Die meisten System-APIs (Speicher, Pakete, Logs, Backups) liefern nur für Mitglieder der Gruppe `administrators` Daten, sonst kommt Fehler 105. Darum einen eigenen User nur für den MCP anlegen und so weit wie möglich einschränken:

1. Systemsteuerung > Benutzer und Gruppe > Erstellen, z.B. `mcp`, langes zufälliges Passwort, Gruppe `administrators`
2. Bei den Berechtigungen für freigegebene Ordner überall "Kein Zugriff" setzen
3. Für diesen User keine 2-Faktor-Authentifizierung, die API kann keine Codes eingeben. Ist 2FA für Administratoren erzwungen, meldet der Login Fehler 403 oder 406
4. Empfohlen: in der DSM-Firewall den Zugriff auf den DSM-Port auf die IP des Docker-Hosts beschränken und die automatische Blockierung aktiv lassen

Der MCP selbst ruft nur lesende Methoden auf, die Rechte des Users begrenzen ihn aber nicht zusätzlich, darum gehören die Zugangsdaten nur in die Portainer-Umgebungsvariablen.

## 2. Cloud-Betrieb (Portainer)

Bei jedem Push auf `main` baut GitHub Actions das Image (`.github/workflows/docker-publish.yml`). Einmalig: Package-Sichtbarkeit auf GitHub auf **Public** stellen oder Portainer Zugang zur Registry geben.

1. Portainer > Stacks > Add stack > Repository, Branch `main`, Compose-Pfad `docker-compose.yml`
2. Environment variables setzen: `DSM_HOST`, `DSM_USER`, `DSM_PASSWORD`, `MCP_AUTH_TOKEN`, optional `DSM_PORT`, `DSM_VERIFY_SSL`, `DSM_TLS_SERVERNAME`, `DSM_TLS_FINGERPRINT` und die Schwellwerte
3. Deploy. Updates später per "Pull and redeploy".

Reverse-Proxy mit TLS auf `<Host-IP>:8432`, Endpoint-Pfad `/mcp`. Der Port ist standardmässig nur auf `127.0.0.1` des Docker-Hosts gemappt; läuft der Proxy auf einem anderen Host, `MCP_BIND_ADDR` auf die LAN-IP setzen. `GET /healthz` ist ohne Token erreichbar und liefert nur `{"status": "ok"}` (Docker-Healthcheck, keine Abfrage der NAS); alle anderen Pfade brauchen das Bearer-Token. In Claude als Remote-MCP mit `https://<subdomain>/mcp` und dem `MCP_AUTH_TOKEN` als Bearer-Token einbinden.

Der Container läuft als unprivilegierter User.

## Tests

```bash
pip install -r requirements-dev.txt
pytest -q
```

Die Unit-Tests prüfen Bearer-Auth, `/healthz`, den DSM-Client (Login, Versionen, Fehlercodes, Logout), die Sperren von `api_query` und die Auswertung im `health_report` mit Fake-Objekten, ohne NAS. Das Zertifikats-Pinning wird gegen einen lokalen HTTPS-Server mit selbstsigniertem Zertifikat geprüft (dafür `cryptography` in `requirements-dev.txt`), inklusive des Falls, dass die Gegenstelle nach dem Holen des Zertifikats ein anderes vorlegt.
