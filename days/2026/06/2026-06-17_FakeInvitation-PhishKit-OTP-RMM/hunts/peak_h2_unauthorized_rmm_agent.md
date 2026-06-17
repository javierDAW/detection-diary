# PEAK Hunt H2 — RMM agents outside the sanctioned baseline (phishing-to-RMM foothold)

**Hypothesis.** If the kit's RMM-delivery branch succeeded, then a host runs a **legitimate remote-
management agent** (ScreenConnect, ITarian, Datto RMM, ConnectWise, LogMeIn Rescue) that is **not**
part of our approved remote-support baseline, landing from a browser download.

**Why baseline deviation.** These agents are signed and widely sanctioned, so they rarely trip AV/EDR.
The detection question is not "is this tool malicious?" but "did **we** install it, and from where?"
Provenance over signature.

## Prepare
- Build the **sanctioned RMM baseline**: which remote-support tools IT approves, their installer
  paths, their relay/instance hostnames, and the expected install method (managed deployment).
- Inventory installed software (`DeviceTvmSoftwareInventory` / EDR inventory) and running services.

## Execute
- Run `kql/rmm_foothold_user_path_execution.kql` to catch RMM binaries launching from
  `\Downloads\` / `\Temp\` or with a browser parent.
- Apply Sigma `rmm_screenconnect_unattended_from_userpath.yml` and
  `rmm_remote_support_applet_from_browser.yml`.
- List installed RMM software and compare against the baseline; flag any tool/relay not on the list.
- On suspect hosts:
  ```
  ps -ef | grep -iE 'screenconnect|connectwise|logmein|lmi_rescue|itsm|datto|aemagent' | grep -v grep
  ```

## Analyze / pivot
- An RMM agent whose relay/instance is **not** an approved corporate tenant is the foothold —
  isolate the host and capture the agent config (relay URL, instance ID, scheduled task/service).
- Correlate the install time with H1 (did the host fetch a lure invitation first?).
- Check for hands-on-keyboard activity after install: new local accounts, credential access,
  lateral movement from that host.

## Document / hand off
- Record each out-of-baseline agent: tool, relay, install path, parent process, install time.
- Uninstall the agent + remove its service/scheduled task; confirm it does not reappear.
- Feed the host into the IR playbook and, if a user was also phished for credentials, into H3.
