# Changelog

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
