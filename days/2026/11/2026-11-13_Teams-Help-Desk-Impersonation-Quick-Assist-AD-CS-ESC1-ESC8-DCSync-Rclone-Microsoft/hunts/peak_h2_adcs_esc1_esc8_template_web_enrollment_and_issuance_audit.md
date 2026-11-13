# PEAK hunt H2 - AD CS ESC1 / ESC8: vulnerable templates, NTLM-reachable web enrollment and certificates issued for someone else

## Prepare

- **Hypothesis:** an attacker with an ordinary domain foothold enrolled certificates for privileged accounts from a template that lets the requester supply the subject (ESC1), or relayed a coerced domain controller NTLM authentication to AD CS Web Enrollment (`/certsrv`) and obtained a "Domain Controller" template certificate for the DC machine account (ESC8), then used PKINIT to get TGTs for those identities.
- **Why:** Microsoft Security Research (2026-10-30): in case 1 three users on one workstation obtained certificates for three highly privileged accounts, and about 90 minutes later sixteen users on a second workstation obtained certificates for eight more; DCSync followed within seconds. In case 2 PetitPotam coerced a DC, the authentication was relayed to web enrollment and a DC certificate was used for PKINIT. Revoking the certificate does not invalidate tickets already issued.
- **Honesty:** no CVE is involved - these are misconfigurations. Microsoft did not publish template names, CA names, request IDs or its hunting queries. Event IDs (4886/4887/4768/4662), the PreAuthType value 16 and the audit settings below are standard Windows knowledge, not case data. All commands are native and read-only; no offensive tooling is needed.
- **Scope:** every Enterprise CA and every published template; CA Security logs (4886/4887/4888), DC Security logs (4768, 5145), IIS logs on web enrollment servers; 30 days or the full CA database for issued-certificate review.
- **Confidence:** high that an enabled template with enrollee-supplied subject plus broad enrollment rights is exploitable; high for a DC machine account authenticating to `/certsrv`; medium for requester/subject mismatch in 4887 (agents and NDES produce it legitimately).

## Execute

**Data sources / content:** `kql/k3_adcs_esc1_esc8_certificate_issuance_pkinit_and_dcsync.kql`, `sigma/04_efsrpc_named_pipe_access_on_domain_controller.yml`, `suricata/helpdesk_impersonation_adcs_esc8_exfil_heuristics.rules` (sids 9993002-9993004).

1. Confirm the CA actually audits (otherwise 4886/4887 never appear):

```powershell
# Author: Jarmi
auditpol /get /subcategory:"Certification Services"
certutil -getreg CA\AuditFilter        # 127 = all CA audit categories
certutil -getreg policy\EditFlags      # check EDITF_ATTRIBUTESUBJECTALTNAME2 (ESC6-style SAN via attributes)
```

2. Template audit for ESC1 - templates allowing enrollee-supplied subject with client-authentication EKU (read-only LDAP):

```powershell
# Author: Jarmi
$cfg = ([ADSI]'LDAP://RootDSE').configurationNamingContext
$s = [ADSISearcher]"(objectClass=pKICertificateTemplate)"
$s.SearchRoot = [ADSI]"LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$cfg"
$s.PropertiesToLoad.AddRange(@('cn','mspki-certificate-name-flag','pkiextendedkeyusage','mspki-enrollment-flag','mspki-ra-signature'))
$s.FindAll() | ForEach-Object {
  $p = $_.Properties
  [pscustomobject]@{
    Template        = $p.cn[0]
    EnrolleeSubject = [bool]([int]$p.'mspki-certificate-name-flag'[0] -band 1)   # CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
    ManagerApproval = [bool]([int]$p.'mspki-enrollment-flag'[0] -band 2)
    RASignatures    = $p.'mspki-ra-signature'[0]
    EKU             = ($p.pkiextendedkeyusage -join ',')
  }
} | Where-Object EnrolleeSubject | Format-Table -AutoSize
certutil -CATemplates                  # which of them are actually published on the CA
```

For each flagged template, review enrollment rights (`dsacls "CN=<template>,CN=Certificate Templates,CN=Public Key Services,CN=Services,$cfg"`) - Domain Users / Authenticated Users enrollment plus client-auth EKU (1.3.6.1.5.5.7.3.2, 1.3.6.1.4.1.311.20.2.2, 1.3.6.1.5.2.3.4 or 2.5.29.37.0) and no manager approval is the ESC1 shape.

3. ESC8 exposure - is web enrollment present, over HTTP, with NTLM and without Extended Protection?

```powershell
# Author: Jarmi  (run on the web enrollment server)
Import-Module WebAdministration
Get-WebBinding -Name 'Default Web Site'
Get-WebConfigurationProperty -PSPath 'IIS:\' -Location 'Default Web Site/CertSrv' -Filter 'system.webServer/security/authentication/windowsAuthentication/extendedProtection' -Name tokenChecking
Get-WebConfigurationProperty -PSPath 'IIS:\' -Location 'Default Web Site/CertSrv' -Filter 'system.webServer/security/authentication/windowsAuthentication/providers' -Name Collection | Select-Object value
```

`tokenChecking` other than `Require`, an HTTP binding, or an `NTLM` provider = relayable (apply KB5005413 guidance).

4. Issued-certificate review on the CA (read-only), last 30 days, then compare requester with subject / SAN:

```powershell
# Author: Jarmi
certutil -view -restrict "Disposition=20,NotBefore>=$((Get-Date).AddDays(-30).ToString('MM/dd/yyyy'))" -out "RequestID,RequesterName,CommonName,CertificateTemplate,NotBefore,SerialNumber" csv > issued_30d.csv
```

Flag rows where `RequesterName` is a normal user but `CommonName` / SAN is a privileged account, bursts of requests from many users in minutes (Microsoft saw 3 then 16 users), and any "Domain Controller" template certificate whose request did not come from the DC itself.
5. Run k3 (needs `<add_known_dc_ips>` etc.). Prioritise `MachineAccountWebEnrollment`, then `PkinitTgtFromNonDc`, then `CaIssuedSubjectNotRequester`.

## Act

- **Expected benign:** enrollment agents, NDES/Intune connectors and smart card issuance stations requesting on behalf of others; DC autoenrollment over RPC (not via `/certsrv`).
- **Action on match:** revoke the rogue certificates AND treat every affected identity as compromised: reset passwords (twice for krbtgt if a DC or DCSync was involved), purge tickets, and remember that revocation does not invalidate TGTs or service tickets already issued. Fix the template (remove enrollee-supplied subject or require manager approval, narrow enrollment rights), enable HTTPS + EPA and disable NTLM on web enrollment (or remove web enrollment), apply KB5005413.
- **Escalation:** any confirmed rogue privileged certificate goes straight to H3 (DCSync and data access by that account).
- **Exit criteria:** zero published templates with enrollee-supplied subject and broad enrollment rights; web enrollment requires EPA over HTTPS or is gone; every certificate issued in the window has a known requester.
