# Changelog

## 0.1

- Erste Version, nur lesend: System, Auslastung, Speicher (Pools, Volumes, Disks mit SMART), Hyper Backup, Updates, Pakete, Freigaben, Verbindungen, Log Center, Security Advisor, Synology Drive.
- `health_report` fasst alles zusammen und listet Auffälligkeiten mit einstellbaren Schwellwerten.
- `api_query` für lesende Aufrufe ohne eigenes Tool, mit Methoden-Allowlist und Sperre sensibler APIs.
- Pro Tool-Aufruf eine DSM-Session mit Logout danach.
