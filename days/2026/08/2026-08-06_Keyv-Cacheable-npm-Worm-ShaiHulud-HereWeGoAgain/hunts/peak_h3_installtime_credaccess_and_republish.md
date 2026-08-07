# PEAK Hunt H3 — Install-time credential access to IMDS/npm, then a package-republish burst

**Hypothesis.** On a compromised build/CI host the Stage-2 collector read cloud and CI credentials (cloud IMDS, Vault, Kubernetes, npm/GitHub tokens) during a package install, then used a stolen npm identity to republish trojanized package versions — visible as an unexpected `node`/`bun` process hitting the metadata service and the npm OIDC/token endpoints, followed by unexpected `npm publish`/registry `PUT` activity from our own identity.

**Prepare (data).** Network telemetry with process attribution (Defender `DeviceNetworkEvents`, Sysmon EID 3, proxy/egress logs), npm registry audit logs / publish history for our maintainer accounts, and GitHub audit logs for new-repo creation.

**Execute (analytic).**
```kql
let imds = dynamic(["169.254.169.254","169.254.170.2"]);
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("node.exe","node","bun.exe","bun")
| where RemoteIP in (imds)
    or RemoteUrl has "registry.npmjs.org/-/npm/v1/oidc/token/exchange"
    or RemoteUrl has "registry.npmjs.org/-/npm/v1/tokens"
    or RemoteUrl has "registry.npmjs.org/-/whoami"
| summarize Hits=count(), Dst=make_set(coalesce(RemoteUrl, tostring(RemoteIP)),10), FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
    by DeviceName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by LastSeen desc
```

**Act.** For each host, correlate the IMDS/npm callouts with the install window (H1) and with any package versions published from our npm accounts in the same period. In the npm registry, audit for versions published "today" that we did not cut, especially version bumps carrying a `preinstall`/`setup.mjs` addition; unpublish/deprecate and rotate the publish token (revoke, not rotate). In GitHub, look for repositories created with the description `Shai-Hulud: Here We Go Again` and a `results/` directory.

**Notes / pitfalls.** Some node services legitimately read cloud metadata at runtime; the discriminator here is that the reader is a short-lived install/test child, not a long-running service, and that it clusters with an `npm install`. Exfiltration is AES-256-GCM ciphertext to GitHub repos and DNS-resolved hosts, so payload inspection will not reveal the stolen data — pivot on the request metadata and the republish side effects instead.

**Refine.** Alert on any `node`/`bun` install child reaching IMDS; enforce IMDSv2 with hop-limit 1 on CI runners; require a human-approval gate and provenance-source review for npm publishes; feed confirmed republished versions into the registry-proxy blocklist.
