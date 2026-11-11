# PEAK hunt H1 - Who holds a credential for our apps? Service principal sign-in failures, failure-then-success and one IP hitting many service principals

## Prepare

- **Hypothesis:** an external party holds a client secret for one or more of our Entra ID app registrations (leaked on GitHub or elsewhere) and is validating it: sign-ins as the service principal fail with `AADSTS7000215` (invalid secret) or `AADSTS7000222` (expired secret) until a still-valid secret works, and a single source IP authenticates to several of our service principals in a short window with mixed results.
- **Why:** Microsoft Threat Intelligence (2026-11-05) reports an unnamed actor using an agentic AI offensive framework (ARTEX) that, from August 2026, ran large volumes of GitHub secret searches (target org name + secret, cloud-service or AI-provider keywords) and, from as early as 2026-10-28, signed in to Entra ID tenants as service principals with leaked application credentials - dozens of apps in multiple tenants - mainly from `199.19.77.84` and `199.19.77.18` (Tor exit). Microsoft states that 7000215 / 7000222 failures from an IP mean someone holds a credential, that failure followed by success is urgent, and that one IP authenticating to 3+ service principals with mixed results is suspicious.
- **Honesty:** no user agents, hashes or domains are published; Microsoft's own hunting query text was not available. IPs may be rotated or reassigned; `65.87.223.26` and `157.22.126.128` are only "may be linked". Microsoft notes IP / user-agent blocking will not stop an agent that changes them, but can alert defenders.
- **Scope:** 14 days of `AADServicePrincipalSignInLogs` (Sentinel) or `EntraIdSpnSignInEvents` (Defender XDR) across every tenant you own; requires the `ServicePrincipalSignInLogs` diagnostic category to be exported.
- **Confidence:** high for the published IPs (as of publication); medium for failure-then-success; low-medium for one IP / many service principals.

## Execute

**Data sources / content:** `sigma/01_agentic_ai_spn_signin_from_published_ips.yml`, `sigma/03_entra_spn_invalid_or_expired_client_secret.yml`, `kql/k1_entra_spn_signins_campaign_ips_multi_spn_and_secret_failure_then_success.kql`.

1. Confirm service principal sign-in logs are actually collected (an empty table is the most common reason this hunt "finds nothing").
2. Run k1. Fill `<add_known_ips>` with your CI/CD egress and NAT ranges, then review `SecretFailureThenSuccess` first, `PublishedCampaignIP` second, `OneIpManyServicePrincipals` last.
3. For every AppId that shows up, list which credentials exist and when they were created (read-only):

```bash
# Author: Jarmi
APPID="<appId>"
az ad app credential list --id "$APPID" --query "[].{keyId:keyId, name:displayName, start:startDateTime, end:endDateTime, hint:hint}" -o table
az ad sp show --id "$APPID" --query "{spId:id, name:displayName, tenant:appOwnerOrganizationId}" -o json
```

4. Map the secret `hint` (first characters of the secret) against what GitHub secret scanning or the YARA hygiene rules found (H3) to identify which secret leaked.
5. Check what the service principal can reach: role assignments (`az role assignment list --assignee "$APPID" --all -o table`) and Graph application permissions - that bounds the blast radius for H2.

## Act

- **Expected benign:** pipelines or scheduled jobs still using a rotated secret (stable source IP inside your ranges, single app, continuous failures with no later success from a new IP); developers mistyping a secret during testing.
- **Action on match:** treat failure-then-success from a non-baselined IP, or any sign-in from the published IPs, as a compromised application identity. Remove the leaked credential (`az ad app credential delete --id <appId> --key-id <keyId>`), add a new secret or - better - move to a certificate or workload identity federation, restart the dependent workloads, revoke refresh tokens / sessions where applicable, and apply a Conditional Access for workload identities location policy or a service principal IP restriction where licensed.
- **Escalation:** pivot to H2 (what the service principal did in ARM, Key Vault, Storage and Graph after the success) using the success timestamp and IP.
- **Detections:** keep Sigma 01 as an alert (re-validate the IPs periodically) and build the k1 failure-then-success join as a scheduled analytics rule.
- **Exit criteria:** every app with 7000215 / 7000222 from an external IP has had all credentials rotated and the leak source removed; no further sign-ins from the source IP.
- **Caveat:** rotating a secret while the attacker already minted tokens does not invalidate those access tokens immediately (typically about an hour of validity); assume the window and review H2 activity until expiry.
