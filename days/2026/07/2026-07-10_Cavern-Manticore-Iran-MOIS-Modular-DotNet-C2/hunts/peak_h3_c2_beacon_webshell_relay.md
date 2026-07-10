# PEAK Hunt H3 — C2 beacon, IIS webshell relay, and second-hop lateral movement

**Hypothesis.** A Cavern-implanted host beacons to a Cavern C2 domain (`hospitalinstallation[.]com`, registered via the Iranian provider Fars Data) over HTTPS/WebSocket, and/or an internal IIS server hosts a `cac.aspx` relay (`CAV3RN_Http_Module`). Access arrives through a trusted IT provider / RMM channel, so lateral movement traces back to a managed-service source.

**Prepare.** Data sources: DNS resolver logs, proxy/TLS SNI logs, `DeviceNetworkEvents`, IIS logs and `DeviceFileEvents` on web servers, plus RMM/SysAid change logs. Assemble the Cavern domain set from the report and your TI feed.

**Execute.**
1. Query DNS/proxy/SNI for `hospitalinstallation.com` and subdomains; expand to newly-registered domains on Iranian registrars (Fars Data) contacted by the side-load host process.
2. On IIS servers, search web roots for `cac.aspx` and any `.aspx` written outside a controlled deployment; review `w3wp.exe` child processes.
3. Look for WebSocket upgrades from server-class hosts to unusual external destinations.
4. Trace inbound access to the affected hosts back to RMM tools or a specific IT provider; check whether a SysAid update preceded the implant, and whether a second provider was the pivot.

**Act.** Block/validate the C2 domain (indicators decay — revalidate first), remove and rebuild any host serving `cac.aspx`, and revoke the trusted-provider/RMM access path used for delivery. Rotate credentials exposed via LSASS dumping.

**Notes.** The framework decouples core comms from per-victim modules for takedown resilience, so infrastructure and behaviour outlast any single hash. Prioritise the delivery channel (trusted relationship) as the durable containment lever.
