# PEAK Hunt H2 — Per-target passkey-themed lookalike subdomains

**Hypothesis.** A user in our org has been (or is being) directed to an O-UNC-066 subdomain of a passkey-themed lookalike domain, staged specifically for our organisation (pattern `<ourbrand>.<passkeybase>.com`). If true, DNS/proxy telemetry contains resolutions/requests to a host whose registrable domain contains the literal string `passkey` and resolves into DDoS-Guard (AS57724) or IQWeb (AS59692).

**Why this is the durable signal.** The operator pre-stages a per-victim subdomain carrying the target's own logo/background. The base domains rotate (`assignpasskey`, `deploypasskey`, `passkeydeploy`, `passkeyadd`, `setpasskey`), but the lexical `passkey` tell plus the hosting ASN is stable across the campaign, and the subdomain often embeds the victim's name.

**Data.** Proxy / secure web gateway logs and DNS resolver logs. See `../sigma/03_pink_proxy_passkey_lookalike_kit_path.yml`. Enrich resolved IPs with ASN.

**Run.**
1. Query DNS/proxy for any hostname whose registrable domain contains `passkey` in the last 60 days.
2. Drop known-good vendors; keep hosts resolving into AS57724/AS59692 or freshly registered (Tucows / Internet Domain Service BS Corp / IQWeb, WHOIS since Apr-2026).
3. Look for a subdomain label matching our brand/abbreviation.
4. For any hit, correlate the requesting user with H1 (did a passkey get registered shortly after?).

**Triage / expected vs benign.** Benign: legitimate identity vendors with `passkey` in the name (validate host + ASN + WHOIS age). Suspicious: brand-embedding subdomain on DDoS-Guard/IQWeb, recently registered. A hit means a user reached the kit — treat the associated account as at-risk and run H1.

**Pivots.** WHOIS registrar/creation date; passive DNS siblings under the same base; other brand subdomains on the same IP (other targeted orgs).
