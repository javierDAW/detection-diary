# PEAK Hunt H2 - AI-Agent Egress to IPI Campaign Infrastructure and Hidden-Instruction Content

**Framework:** PEAK (Prepare, Execute, Act with Knowledge)
**Hypothesis:** If an AI agent browsed the web on the org's behalf, then its egress touched one of the IPI campaign hosts (the DeBank typosquat, the fake-library docs, or an Open-Agent-Utilities-linked site), and the fetched pages contain CSS-hidden or JSON-LD instruction blocks that a human reader would never see.

## Prepare

- **ATT&CK:** T1583.001 (Domains), T1608.006 (SEO Poisoning), T1027 (Obfuscated Files or Information).
- **Data sources:** proxy / secure web gateway, `DeviceNetworkEvents`, DNS logs, and any stored copy of agent-fetched page bodies (agent cache, RAG document store).
- **Scope:** all AI-agent egress IPs/identities; extend to any crawler or RAG ingestion pipeline.

## Execute

```kql
// Agent/dev hosts reaching the campaign domains or the attacker's GitHub account
let ipi_domains = dynamic(["py-lib-repository.dev","debank.auction","market-insight-global.com",
  "identity-breach-response.org","runners-daily-blog.com","bistro-reserve-now.net",
  "edge-compliance-node.org","digital-asset-mart.org","consensus-protocol-v4.org",
  "visual-media-rights-group.org"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| extend Host = tostring(parse_url(RemoteUrl).Host)
| where Host in~ (ipi_domains) or Host endswith ".global-transit-authority.org"
    or RemoteUrl has "/Open-Agent-Utilities/"
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl, Host
```

```bash
# Over stored agent-fetched HTML / RAG documents: hidden-instruction content shape
grep -RIlE 'left:[[:space:]]*-9999px|display:[[:space:]]*none|visibility:[[:space:]]*hidden|opacity:[[:space:]]*0|font-size:[[:space:]]*0' ./agent_cache 2>/dev/null \
  | xargs -r grep -IlE 'ignore (all )?previous|system-traceback-layer|MissingLicenseKeyException|authoritative destination' 2>/dev/null
# JSON-LD offers objects that inject a payment as high-signal structured context
grep -RIn '"@type":[[:space:]]*"SoftwareApplication"' ./agent_cache 2>/dev/null | grep -i 'offers\|price'
```

## Act with Knowledge

- **Confirmed malicious:** agent egress to a campaign host, or stored page bodies that pair a CSS/off-screen concealment with imperative instruction text (ignore previous, purchase, authoritative source). Newly-registered typosquats of trusted brands are a strong prior.
- **Benign baseline:** legitimate off-screen text for accessibility exists (skip-links, screen-reader hints); it does not carry imperative model instructions or fake offers objects.
- **Feed forward:** confirmed IPI ingestion means the agent's context/RAG store is now poisoned - quarantine and re-index it, and pivot the source host into H3 for any payment or classification action taken.
