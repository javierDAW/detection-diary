# PEAK Hunt H1 — search-ms / WebDAV LNK delivery sequence (SpearSpecter / APT42)

**Prepare**

- Hypothesis: If a user was social-engineered into a SpearSpecter link, the host shows a `search-ms` prompt followed by an outbound WebDAV (SSL) mount to an external host and then a `curl` download that is renamed to a `.bat` and executed.
- Scope: user workstations, especially those of senior defense/government staff and their family/personal-use devices if managed.
- Data: Sysmon EID 1 (process create), EID 3 (network), EID 22 (DNS); Defender `DeviceProcessEvents`/`DeviceNetworkEvents`; proxy logs.
- ATT&CK: T1204.001, T1218.011, T1204.002, T1105, T1059.003.

**Execute**

1. Find WebDAV reach-outs: `rundll32.exe` command lines containing `davclnt.dll` + `DavSetCookie` + `@SSL` to an external host (baseline internal SharePoint/WebDAV first).
2. Within 15 minutes on the same device, find `curl.exe` writing `vgh.txt` (or any `.txt`) then a rename to `*.bat`, or a `cmd /c ... & rename ... & %tmp%` pattern.
3. Correlate DNS/TLS to `*.somee.com`, `*.workers.dev` (esp. `line.completely.workers.dev`) around the same window.
4. Confirm the origin: was `explorer.exe` or a browser the parent of the `rundll32`/`cmd` activity (user-driven `search-ms` prompt)?

**Act**

- True positive: isolate host, preserve WebDAV INetCache, pull the staged `.bat`/loader, pivot to H2/H3, and warn the approached user (and family accounts).
- Tuning: allowlist internal WebDAV/SharePoint FQDNs; treat external-host `DavSetCookie` as high-signal.

**Knowledge**

- Record any new delivery domains and Workers subdomains into `iocs.csv`. Note whether the `search`/`search-ms` handler is present on the estate (candidate hardening).
