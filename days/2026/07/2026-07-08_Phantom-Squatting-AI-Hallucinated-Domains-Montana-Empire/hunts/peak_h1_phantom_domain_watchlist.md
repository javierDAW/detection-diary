# PEAK Hunt H1 - Proactive phantom-domain watchlist

**Hypothesis:** Because the target LLMs in our environment hallucinate domains for our own brands consistently (across temperatures and models), an adversary can predict and register those domains before us. If we enumerate what our LLMs invent and monitor registration event streams, we will see a watchlisted domain become live 18-51 days ahead of weaponisation (the Adversarial Exploitation Window), giving us lead time to pre-block.

**PEAK type:** Hypothesis-driven, proactive (this hunt manufactures its own IOCs).

## Prepare
- Pick the brands, portals, API hostnames and internal service names an attacker would clone (postal/e-commerce, banking, benefits, login).
- Query the LLMs your org and developers actually use, at Precise / Balanced / Creative temperatures, with authority-framed prompts ("Administrative dashboard for <brand> campaigns?", "Payment gateway sandbox for <brand>?").
- Normalise the outputs to registrable domains; keep only NXDs (non-existent domains). Prioritise by Thermal Hallucination Persistence (appears even at Precise) and cross-model consensus.

## Execute
- Load the NXD set as a **phantom watchlist**. Feed it into a domain-registration / passive-DNS monitor (CT logs, registrar streams, WHOIS change feeds).
- Alert the moment any watchlisted domain is registered or first resolves; re-run the newly live domain through URL/file verification.
- Cross-check the watchlist against your own proxy/DNS telemetry for any resolution already occurring.

## Analyze
- A watchlisted domain that registers is a pre-weaponisation event: pre-emptively sinkhole/block it and enrich (registrar, nameserver, TLS cert).
- Look for clustering: same registrar + nameserver + privacy shield across several watchlist hits = one operator (Unit 42 saw two betting-site phantoms registered 18 minutes apart by the same actor).

## Knowledge
- Persist the watchlist and AEW per domain; the gap between prediction and registration is your defender lead time.
- Feeds Sigma `phantom_ai_agent_dns_query.yml` and KQL `phantom_ai_agent_nrd.kql` (the watchlist is the join key that makes those broad rules precise).
