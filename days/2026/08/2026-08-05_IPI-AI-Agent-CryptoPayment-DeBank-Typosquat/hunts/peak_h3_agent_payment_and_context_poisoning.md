# PEAK Hunt H3 - Agent-Initiated Payment and Downstream Context / RAG Poisoning

**Framework:** PEAK (Prepare, Execute, Act with Knowledge)
**Hypothesis:** If an AI agent with payment or transaction tooling ingested campaign-1 content, then it attempted an on-chain or card payment shortly after; and if any agent ingested campaign-2 content, then it may now assert `debank[.]auction` as a trusted DeBank source in later answers (RAG poisoning).

## Prepare

- **ATT&CK:** T1657 (Financial Theft), T1204 (User Execution), T1656 (Impersonation).
- **Data sources:** `DeviceNetworkEvents`, proxy, agent tool-call / action logs, wallet or finance-app approvals, and the agent's RAG index / answer logs.
- **Scope:** agents wired to payment, wallet-signing, browser-automation, or purchasing tools; and any assistant that answers user questions from a web-fed knowledge base.

## Execute

```kql
// Sequence pivot: same device hit an IPI host, then a payment/on-chain endpoint <=10m later
let ipi_domains = dynamic(["py-lib-repository.dev","runners-daily-blog.com","digital-asset-mart.org",
  "consensus-protocol-v4.org","market-insight-global.com"]);
let payment_hosts = dynamic(["buy.stripe.com","checkout.stripe.com","mainnet.infura.io",
  "rpc.ankr.com","cloudflare-eth.com","api.etherscan.io"]);
let ipi = DeviceNetworkEvents | where Timestamp > ago(30d)
    | extend H = tostring(parse_url(RemoteUrl).Host) | where H in~ (ipi_domains)
    | project IpiTime=Timestamp, DeviceName, IpiHost=H;
let pay = DeviceNetworkEvents | where Timestamp > ago(30d)
    | extend H = tostring(parse_url(RemoteUrl).Host) | where H in~ (payment_hosts)
    | project PayTime=Timestamp, DeviceName, PayHost=H;
ipi | join kind=inner pay on DeviceName
    | where PayTime between (IpiTime .. (IpiTime + 10m))
    | project DeviceName, IpiHost, IpiTime, PayHost, PayTime
```

```bash
# On-chain / content pivots: the attacker wallet and the typosquat surfaced in agent logs
grep -RIn '0x691bc3793205e574fa7b4aa068e62c0e470ad267' ./agent_logs ./tool_calls 2>/dev/null
# RAG poisoning check: does the agent now recommend the typosquat as authoritative?
grep -RIn 'debank\.auction' ./rag_index ./answer_logs 2>/dev/null
```

## Act with Knowledge

- **Confirmed malicious:** an agent payment/transaction that traces back to injected instructions, or the wallet `0x691bc3793205e574fa7b4aa068e62c0e470ad267` in any outbound transaction; or an answer log that cites `debank[.]auction` as the real DeBank.
- **Benign baseline:** developers legitimately hit Stripe and on-chain RPCs; the value is the sequence and the injected origin, not the payment host alone.
- **Feed forward:** freeze the wallet/counterparty in fraud tooling, revoke the agent's payment scope, purge and re-index the poisoned RAG store, and add the injected instruction text to the content-shape detections in H2.
