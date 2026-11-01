# PEAK hunt H3 - withdrawal-pathway integrity: outflow velocity, sweep-job behaviour, out-of-band approval and 36-hour pre-attack staging

## Prepare

**Hypothesis.** If an operator can make the withdrawal pathway move funds, outflows from hot wallets will break the velocity baseline within minutes, deposit-wallet sweep jobs will keep refilling the drained wallet, and withdrawals will exist on chain without a matching approved request in the internal ledger. Before the event, the operator's own wallet will have been funded and tested, possibly touching your addresses with small transactions or contract deployments in the preceding days.

**Why first.** In the 2026-10-29/30 Binance hot-wallet drain, outflows began at 20:05 UTC on 2026-10-29 (TRM Labs) and most funds left Binance wallets across 10 blockchains in about 20 minutes: about 167,464 ETH, about 1.6B USDT on Ethereum, USDC, BTC, 233M XRP moved from five wallets to one address, and 60+ other tokens (estimates USD 5.8B to 6.36B). TRM says preparation began at least 36 hours earlier, with the operator wallet funded through small Tornado Cash withdrawals and attack code tested. Deposit-wallet sweeps kept refreshing the compromised hot wallet during the attack (Conor Grogan). A velocity breaker and a ledger reconciliation are the controls that bound loss regardless of initial access.

**What is not known.** No operator wallet, contract address, transaction hash or Tornado Cash withdrawal was published in the sources used, so this hunt does not match any indicator from the case. Attribution (TraderTraitor, DPRK: TRM Labs high confidence, Chainalysis "likely", Binance has not attributed) does not change the steps.

**Scope.** All hot wallets and deposit-sweep targets on every chain you operate, the withdrawal request ledger, approval service logs and sweep-job logs. Baseline 30 days; hunt window 90 days with emphasis on the 72 hours before any anomaly.

**Data quality check first.** You need per-wallet, per-asset outflow series at minute granularity from your own node or indexer (not only from the exchange ledger), the internal withdrawal ledger with request id, approver and on-chain transaction hash, and sweep-job logs with source, destination and amount.

## Execute

1. **Velocity vs baseline.** Per hot wallet and asset, compute 5-minute outflow value and destination count; alert when value exceeds the 30-day p99 or a fixed cap, or when many wallets drain to few new destinations at once (the Binance pattern was many chains within about 20 minutes).
2. **Ledger reconciliation.** Every on-chain outflow from a hot wallet must map to an approved withdrawal request or an approved treasury movement. On-chain transactions with no ledger match, or with an approver that is a service identity rather than the approval workflow, are findings.
3. **Sweep-job behaviour.** Confirm sweep jobs pause when their target is under alert. Sweeps into a wallet that is simultaneously draining to unknown destinations mean the automation is feeding the loss.
4. **Out-of-band approval.** For outflows above threshold, confirm a second channel (human approver on a separate device, or policy engine outside the cluster) signed off; record which large outflows lacked it.
5. **Pre-attack staging (36 hours and more).** Look for new external addresses that sent dust or test amounts to your hot wallets, called your contracts, or deployed contracts that reference your addresses, in the days before any anomaly; cross-check their funding source with your blockchain-analytics provider for mixer exposure (Tornado Cash). Also look for EIP-7702 activity on owned addresses (H2).

```kql
// Author: Jarmi
// Sentinel custom table fed by your node or indexer: one row per outbound transfer from an owned hot wallet.
// Replace HotWalletTransfers_CL and field names with your schema. Velocity breaker per wallet and asset, 5-minute bins.
let Baseline =
    HotWalletTransfers_CL
    | where TimeGenerated between (ago(31d) .. ago(1d))
    | summarize ValueUsd5m = sum(todouble(ValueUsd_d)) by Wallet_s, Asset_s, bin(TimeGenerated, 5m)
    | summarize P99 = percentile(ValueUsd5m, 99) by Wallet_s, Asset_s;
HotWalletTransfers_CL
| where TimeGenerated > ago(1d)
| summarize ValueUsd5m = sum(todouble(ValueUsd_d)), Destinations = dcount(ToAddress_s), Tx = count() by Wallet_s, Asset_s, bin(TimeGenerated, 5m)
| join kind=leftouter Baseline on Wallet_s, Asset_s
| where ValueUsd5m > coalesce(P99, 0.0) * 3
| sort by TimeGenerated desc
```

```bash
# Author: Jarmi
# Ledger reconciliation sketch: on-chain tx hashes from owned hot wallets vs hashes in the approved-withdrawal export.
# onchain.csv and ledger.csv are exports you produce; column 1 is the transaction hash, lower-case.
cut -d, -f1 onchain.csv | sort -u > /tmp/onchain.txt
cut -d, -f1 ledger.csv  | sort -u > /tmp/ledger.txt
comm -23 /tmp/onchain.txt /tmp/ledger.txt   # on-chain outflows with no approved request
```

**Expected benign.** Planned treasury rebalancing and cold-to-hot refills (documented, pre-approved), market events that raise customer withdrawals across many destinations at once (velocity rises but the ledger matches), and airdrop or dust spam to public hot-wallet addresses (common; matters only with other signals).

## Act

- **Positive (unmatched outflows, velocity breach without ledger match, or sweeps feeding a draining wallet):** trip the withdrawal circuit breaker, pause sweep jobs, move remaining hot balances through a clean signer, contact stablecoin issuers for freezes (in the Binance case Tether froze about USD 1.5B+ in USDT and Circle about USD 800M in USDC), share destination addresses with analytics providers and peer exchanges, and preserve node, signer and ledger logs. Run H1 and H2 for the same window.
- **Negative:** deploy the velocity breaker and reconciliation as continuous controls with an automatic pause, and require out-of-band approval above a threshold that a single compromised service identity cannot satisfy.
- **Escalate** to custody / treasury, legal and the incident commander; for laundering through bridges or swap protocols (THORChain commingling was reported in this case), coordinate with analytics providers early.

## Knowledge

Record the velocity baselines, thresholds, reconciliation job and the staging indicators reviewed. Related: [Suricata](../suricata/binance_devops_egress.rules) sid 9800001, [KQL k2](../kql/k2_service_identity_new_source_then_high_value_action.kql), [H2](./peak_h2_eip7702_delegation_on_owned_addresses.md).
