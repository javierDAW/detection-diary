# PEAK Hunt H2 — DOGLEASH passive backdoor on a Linux host/appliance

**Hypothesis.** A Linux system (router, IoT appliance, or server with a firewall) is running DOGLEASH: a passive C backdoor that binds a hardcoded local TCP port, decodes inbound TCP with a hardcoded password, and executes commands via `/bin/sh -c`, reads files, or runs code in memory based on a small set of command codes.

**Prepare.** Data sources: `DeviceProcessEvents`/`DeviceNetworkEvents` (Defender for Endpoint Linux), auditd (execve, connect, bind), and host firewall/socket state (`ss -ltnp`, `iptables -S`). Fields: listening sockets and owning process, child `/bin/sh -c` processes with an unusual parent, iptables ruleset, ELF paths in `/tmp`, `/var/tmp`, `/dev/shm`.

**Execute.**
1. Snapshot listeners: `ss -ltnp` on suspect hosts and flag any listener owned by an unsigned/ELF binary in a world-writable path or with a random/short name.
2. Correlate each suspicious listener with the iptables ruleset — DOGLEASH's loader adds an explicit `INPUT ACCEPT` for its bind port; a listener whose port has a dedicated ACCEPT rule added at the same time is high signal.
3. Look for short-lived `/bin/sh -c` children spawned by that listener process (command execution), and for the binary self-reading/renaming files (backup-then-overwrite pattern) or getting OS info (`uname`-like enumeration).
4. Hash the binary and run the DOGLEASH YARA/hash set; extract strings for the ff-agent/exploit-themed artifacts.

**Act.** Confirmed → preserve memory + binary, kill the listener, remove the iptables ACCEPT rule and the ELF, and check for a companion LONGLEASH relay and JARLEASH JAR. Treat the host as fully compromised (arbitrary command exec) — rebuild rather than clean where feasible.

**Notes.** Because it is passive, DOGLEASH generates almost no outbound noise until the operator connects; the durable artifacts are the listener + the matching firewall-allow rule, not C2 beaconing.
