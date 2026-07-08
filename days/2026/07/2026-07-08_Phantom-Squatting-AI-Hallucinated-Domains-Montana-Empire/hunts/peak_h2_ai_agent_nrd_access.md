# PEAK Hunt H2 - AI agent reaching a newly-registered / unreputed domain

**Hypothesis:** An AI coding assistant, CLI or autonomous agent in our environment followed a domain it hallucinated - fetching, opening or downloading from a domain that is newly registered or carries no reputation - without a human verifying it first.

**PEAK type:** Hypothesis-driven, reactive.

## Prepare
- Inventory the AI tooling that can make outbound requests: editor agents, `node`/`python` MCP servers and agent runtimes, local model CLIs, doc/automation bots.
- Obtain a newly-registered-domain (NRD, age < 30 days) feed and/or the H1 phantom watchlist.

## Execute
- Pull agent-initiated egress: `DeviceNetworkEvents` where `InitiatingProcessFileName` is an AI-agent binary; extract the destination host from `RemoteUrl`.
- Left-join the host against the NRD feed and the phantom watchlist.
- Repeat over DNS (`dns_query`) and proxy logs for coverage where process attribution is missing.

## Analyze
- Prioritise hits to domains registered within the AEW band and to any watchlisted domain.
- Pivot on the process tree: did the agent auto-open/download (no human in the loop)? Did a download utility spawn as a child?
- Confirm whether a kit artifact (see H3) or an APK was retrieved.

## Knowledge
- Any true positive justifies a policy control: block agents from auto-opening model-generated links, require domain verification before an agent fetches.
- Backs Sigma `phantom_ai_agent_dns_query.yml` and KQL `phantom_ai_agent_nrd.kql`; the NRD/watchlist join is what converts the broad process filter into signal.
