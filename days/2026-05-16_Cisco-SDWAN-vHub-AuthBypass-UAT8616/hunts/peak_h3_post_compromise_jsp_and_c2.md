# PEAK Hunt H3 — JSP webshell drop plus egress to Talos-curated post-compromise C2

## Hypothesis (H3)

A Catalyst SD-WAN Manager (vManage) appliance that did not receive the February 2026
fixes for CVE-2026-20133, CVE-2026-20128 and CVE-2026-20122 has been compromised by one
of the ten activity clusters Talos described on 14-May-2026, which used ZeroZenX Labs'
public PoC and accompanying JSP shell ("XenShell") to deploy webshells and follow-on
implants (AdaptixC2, Sliver, NimPlant variant, XMRig, gsocket). We expect to find either
(a) a JSP file with one of the known cluster filenames on the appliance, or (b) outbound
egress from the appliance to one of the curated cluster IP addresses.

## Why this discriminates

The cluster filenames (`20251117022131.jsp`, `conf.jsp`, `sysv.jsp`, `sysinit.jsp`,
`vmurnp_ikp.jsp`, plus the upstream `cmd.jsp`) are specific to the public PoC and the
forks of public webshells (Godzilla, Behinder, XenShell). The C2 IP list is the curated
Talos set for clusters 1-10, observed in March-May 2026. A Catalyst SD-WAN appliance has
no legitimate reason to talk to any of those endpoints.

## Expected benign vs malicious

- **Expected benign:** no benign reason for these specific filenames or for egress to
  these C2 IPs from an SD-WAN controller. If a match is found, treat as compromise until
  proven otherwise.
- **Expected malicious:** a JSP file in the Tomcat webapps deploy path on vManage whose
  name matches one of the cluster filenames; OR outbound traffic from the controller to
  one of the cluster IPs.

## Queries

Filesystem hunt on the controller:

```bash
find / -type f -name "*.jsp" \( \
   -name "20251117022131.jsp" -o \
   -name "conf.jsp" -o \
   -name "sysv.jsp" -o \
   -name "sysinit.jsp" -o \
   -name "vmurnp_ikp.jsp" -o \
   -name "cmd.jsp" \) 2>/dev/null
```

KQL — egress to cluster IPs (see `kql/sdwan_post_compromise_c2_egress_known_clusters.kql`
for the full curated set).

PCAP / firewall hunt — any of the curated C2 IPs:

```bash
zgrep -E "(194\.163\.175\.135|23\.27\.143\.170|83\.229\.126\.195|13\.62\.52\.206|176\.65\.139\.31|47\.104\.248\.7)" /var/log/firewall/*.log*
```

## Action on match

1. Pull the JSP file content immediately and hash it (`sha256sum`). Cross-reference
   against the Cisco-Talos IOCs GitHub repo for the same month.
2. Collect process listings and identify any non-Cisco binary running from `/tmp/`,
   `/var/tmp/`, `/dev/shm/`, or `~vmanage-admin/`.
3. Hunt for the daemon activation patterns documented by Talos: AdaptixC2 launched as
   `systemd-resolved`, gsocket activated via `.profile`, XMRig launched via `miner.sh`.
4. Network-isolate the controller pending re-image. Webshells observed in these clusters
   give bash command execution; treat the host as fully compromised.

## References

- https://blog.talosintelligence.com/sd-wan-ongoing-exploitation/
- https://github.com/Cisco-Talos/IOCs/tree/main/2026/05
- https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v
