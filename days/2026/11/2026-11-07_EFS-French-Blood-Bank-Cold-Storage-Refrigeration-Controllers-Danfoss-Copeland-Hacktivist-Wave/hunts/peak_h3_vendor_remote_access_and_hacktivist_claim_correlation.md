# PEAK hunt H3 - Vendor / third-party remote-access accounts and hacktivist-claim correlation

## Prepare

- **Hypothesis:** credentials of a refrigeration provider or vendor remote-access account were used to reach our controllers outside the agreed window, and / or one of our sites or providers appears in hacktivist Telegram claims about refrigeration attacks.
- **Why:** the EFS incident hit one of its refrigeration-equipment providers (NPR: "one vendor"; Medical Device Network: three cold-storage facilities managed by Coolworld for EFS - unreconciled). NoName057(16) and Z-Pentest Alliance claimed refrigeration attacks across Europe on Telegram, alleging hacked credentials and naming Danfoss and Copeland devices; these claims are NOT shown to concern EFS and experts are skeptical. No attribution is confirmed and no initial access vector is published.
- **Scope:** all third-party / vendor accounts with access to refrigeration controllers (VPN, remote-desktop tools, provider cloud portals, shared controller logins); public hacktivist claims for the last 60 days.
- **Confidence:** low. Both signals are indirect; a claim without a matching log event is not evidence, and a night-time vendor login can be a genuine alarm call-out.

## Execute

**Data sources:** Entra ID `SigninLogs` (`kql/k3_signin_vendor_remote_access_outside_window.kql`), VPN / remote-access gateway logs, `DeviceLogonEvents` on jump hosts, proxy logs (`sigma/03_vendor_remote_access_posts_to_controller_web_ui.yml`), CTI feed or analyst monitoring of public hacktivist channels, provider incident notifications.

1. Build the vendor account register: account, provider, MFA (y/n), allowed source, agreed window, controllers in scope, owner. Flag shared or generic accounts.

2. Run `k3` and list successful vendor sign-ins outside the window, from new countries or without MFA.

3. On jump hosts without Entra ID integration, review interactive and remote-interactive logons by vendor accounts:

```bash
# Author: Jarmi
# Linux jump host example; adapt for Windows (DeviceLogonEvents / Security 4624 LogonType 10)
grep -hE 'Accepted (password|publickey) for' /var/log/auth.log* 2>/dev/null \
  | grep -E '<add_vendor_remote_access_accounts>' \
  | awk '{print $1" "$2" "$3" "$9" "$11}' | sort | uniq -c | sort -rn
```

4. Collect public claims (date, group, country, sector, device brand, screenshots) and compare each with our sites, providers and brands from H1. Match only on concrete details (site names, screenshots of our HMI, timestamps), never on brand alone.

5. For every claim that matches one of our assets, pull H2 data for the claimed date and the vendor sign-ins of the preceding 72 hours.

## Act

- **Findings handling:** two tables: (a) vendor sign-ins outside the window with ticket / call-out justification; (b) claims vs assets with match quality (`concrete`, `brand-only`, `none`).
- **Immediate response:** disable or reset any vendor account with an unexplained out-of-window success; enforce MFA and per-person accounts; restrict vendor access to a brokered, recorded session with just-in-time approval.
- **Escalation:** provider security contact and national CERT for any concrete claim match or unexplained vendor session that coincides with an H2 parameter change.
- **Exit / validation criteria:** every vendor account is personal, MFA-protected and window-restricted; no unexplained out-of-window success in 30 days; claim register reviewed weekly.
- **Caveat:** hacktivist claims are often exaggerated or recycled; do not publish or act on attribution without corroborating telemetry.
