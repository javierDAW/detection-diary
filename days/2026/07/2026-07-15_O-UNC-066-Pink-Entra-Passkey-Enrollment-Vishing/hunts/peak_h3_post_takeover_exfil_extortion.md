# PEAK Hunt H3 — Post-takeover SharePoint/OneDrive exfil staged for Pink extortion

**Hypothesis.** After a passkey-persisted takeover, the operator has begun bulk collection from SharePoint/OneDrive to stage data for the Pink data-leak site. If true, a compromised account shows an abnormal burst of file access/downloads shortly after a suspicious passkey registration or actor-ASN sign-in.

**Why this is the durable signal.** Pink's motive is data extortion (DLS live since 2026-05-31, 72-hour deadline). The takeover only matters if data leaves; the exfil burst is the impact artefact and is visible in cloud audit even though the initial access left little host trace.

**Data.** `CloudAppEvents` (SharePoint/OneDrive `FileDownloaded` / `FileSyncDownloadedFull` / `FileAccessed`) — see `../kql/post_takeover_sharepoint_onedrive_exfil.kql`. Optionally `OfficeActivity`.

**Run.**
1. For accounts flagged in H1 (rogue passkey) or H3-adjacent (actor-ASN sign-in), pull all cloud file activity for +/- 24h around the event.
2. Summarise distinct files and volume per account per hour; flag bursts above your migration/sync baseline.
3. Check for access to sensitive libraries the user does not normally touch, and for a new client/app or unmanaged device driving the access.

**Triage / expected vs benign.** Benign: OneDrive sync on a new device, a genuine bulk migration. Suspicious: a large, fast, breadth-first pull immediately after a questionable passkey registration or actor-ASN login. Escalate: contain the account, preserve the audit trail, scope what was accessed for breach notification.

**Pivots.** Downloading IP/ASN; unmanaged-device id; the passkey `displayName` from H1; whether an extortion message later arrives from the same mailbox.
