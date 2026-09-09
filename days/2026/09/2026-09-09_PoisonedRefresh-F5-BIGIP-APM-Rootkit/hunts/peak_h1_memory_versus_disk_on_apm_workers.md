# PEAK hunt H1 - Memory versus disk: finding a web shell that never touches the disk

## Prepare

**Hypothesis.** If an APM appliance runs the PoisonedRefresh implant, then the PHP code that an Apache worker executes for
`apm_css.php3`, `full_wt.php3` or `webtop_popup_css.php3` differs from the file on disk, and the worker shows the memory-permission
changes Sophos describes around `libphp`. File integrity monitoring on the three scripts will report nothing, because Sophos states the
shell "does not need to exist in its final form on disk".

**Why first.** This is the one check the implant is designed to defeat, and it is the control Sophos recommends adding to playbooks for
critical web servers: compare in-memory module contents with the on-disk copy, and inspect runtime behaviour, not only files.

**Scope.** Every BIG-IP APM appliance that ever ran a release below the fixed ones for CVE-2025-53521 (15.1.10.8, 16.1.6.1, 17.1.3,
17.5.1.3), including appliances patched after exposure, because the implant is reported to survive upgrade images.

**Data quality check first.** Confirm you can obtain a root shell and that F5 support is aware before you touch a suspect device; some
checks (memory capture) are best done with F5's guidance, and a restart destroys the evidence.

## Execute

```bash
# Author: Jarmi
# On the appliance, as root. Read-only checks: do not restart httpd before you have captured memory.
ls -l /run/bigtlog.pipe /run/bigstart.ltm 2>&1
lsof -n 2>/dev/null | grep -E 'bigtlog|bigstart'
getenforce; semanage permissive -l 2>/dev/null | grep -E 'httpd_t|mount_t|apd_t'
sys-eicheck 2>&1 | tail -20
sha256sum /usr/sbin/httpd /usr/bin/umount        # compare with a clean copy of the SAME release or hotfix
```

```bash
# Author: Jarmi
# For each Apache worker: look at how libphp is mapped. Anonymous writable+executable pages next to libphp are worth a memory capture.
for pid in $(pgrep -x httpd); do
  echo "== $pid"; grep -E 'libphp' /proc/$pid/maps | head -8
done
```

```kql
// Sentinel: appliances whose forwarded logs already show a SELinux or bash-through-iControl signal (see kql/k1).
// Run k1_bigip_audit_log_bash_and_selinux_changes.kql and sort by SignalClasses.
```

## Act

**Any of `/run/bigtlog.pipe`, `/run/bigstart.ltm`, a failing `sys-eicheck` on `umount` or `httpd`, or SELinux domains made permissive**
means treat the appliance as compromised. Capture volatile evidence and a qkview first, open an F5 case, then follow the playbook: rebuild
from known-good media and rotate everything the device handled.

**A hash or size difference on `umount` or `httpd` alone** is a strong lead but not proof: F5 notes the values differ between releases and
engineering hotfixes, so compare against the exact release.

**No hits** do not clear the device. The implant is memory-resident and a restart removes the running copy while the install-image
persistence may remain. Move to H2 and H3, and keep the device on the review list until it has been rebuilt or confirmed by F5.
