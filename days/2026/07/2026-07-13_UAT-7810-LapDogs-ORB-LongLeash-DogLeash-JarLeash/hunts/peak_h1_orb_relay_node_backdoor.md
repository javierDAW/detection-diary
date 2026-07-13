# PEAK Hunt H1 — SOHO/edge device turned into a UAT-7810 ORB relay node

**Hypothesis.** An internet-facing SOHO or embedded networking device (Ruckus wireless router or similar) has been compromised via an unpatched n-day and is now running a UAT-7810 backdoor (DOGLEASH passive listener and/or LONGLEASH relay implant), participating in an Operational Relay Box network.

**Prepare.** Data sources: device/router syslog, firewall change logs, Defender for Endpoint (Linux) `DeviceProcessEvents`/`DeviceFileEvents`/`DeviceNetworkEvents` where an EDR agent is present, and network egress/NetFlow from the management segment. Fields: process image + command line, iptables/nftables rule changes, new listening sockets, outbound destination IP/port, TLS cert subject. Baseline which appliances are patched against CVE-2020-22653/22658 and CVE-2023-25717.

**Execute.**
1. Enumerate edge devices exposed to the internet and cross-check firmware against the three Ruckus CVEs (plus ASUS AiCloud CVE-2025-2492); unpatched + internet-facing is the target population.
2. On instrumented hosts, hunt for a shell downloader (`wget`/`curl`/`tftp`/`busybox`) pulling from a raw dotted-quad on port `8088` or `2222`, followed by `chmod +x` and execution from a world-writable path.
3. Look for an `iptables`/`nftables` `INPUT ... ACCEPT` rule opening a specific high TCP `--dport`, then a new process bound to that port (DOGLEASH is a passive backdoor — it listens, it does not beacon).
4. Retro-hunt the LONGLEASH/DOGLEASH/JARLEASH/LEASHTEST SHA256 set (iocs.csv) and run the YARA structure rules against router firmware dumps / recovered ELF+JAR files.

**Act.** Confirmed relay node → capture volatile memory and the ELF/JAR before rebooting (self-cleaning LONGLEASH wipes traces on tamper), image the device, factory-reset + patch firmware, rotate device and management credentials, and block/monitor the outbound port-99 relay path. Feed fresh infra to CTI (H3).

**Notes.** DOGLEASH is server-side: the tell is an unexpected inbound-allow firewall change and a new listener, not an outbound beacon. LONGLEASH beacons and relays — hunt both shapes.
