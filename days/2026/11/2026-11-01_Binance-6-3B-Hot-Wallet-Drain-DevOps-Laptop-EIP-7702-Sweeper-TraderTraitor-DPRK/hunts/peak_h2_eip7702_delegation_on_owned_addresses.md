# PEAK hunt H2 - an EIP-7702 delegation was set, or attempted, on an address the organization controls

## Prepare

**Hypothesis.** If an operator obtained the ability to sign as one of your hot wallets (directly or through a service that signs on its behalf), they can submit a type-4 (EIP-7702) transaction whose authorization list delegates that EOA to an attacker-controlled contract. Once delegated, the EOA's code becomes the delegation designator `0xef0100` followed by the 20-byte delegate address, and any call to the EOA runs the delegate's code, for example a sweeper that only the attacker wallet can operate. Successful delegations leave non-empty code on the EOA; failed attempts leave type-4 transactions whose authorization tuples reference your addresses.

**Why first.** In the 2026-10-29/30 Binance hot-wallet drain, TRM Labs and Blockaid describe the Ethereum leg as EIP-7702 delegation that made hot wallet "Binance 14" execute an attacker-controlled sweeper contract. Blockaid reports that one type-4 transaction carried 50 EIP-7702 authorizations tied to consecutive nonces and only 1 of 50 hit, so the attempts themselves are on chain. Coinbase's Conor Grogan noted that deposit-wallet sweeps kept refreshing the compromised hot wallet during the attack. Ethlabs says EIP-7702 itself is not broken: the issue is who could sign. Checking your own addresses for a delegate is cheap, exact and does not depend on any IOC.

**What is not known.** No wallet address, contract address, transaction hash or sweeper bytecode is used here. How the authorization signatures were produced was not published; Binance says it found no evidence of a wallet private-key leak. This hunt does not reconstruct the Binance case; it checks your own estate.

**Scope.** Every EOA your organization controls on EVM chains that have activated EIP-7702 (hot wallets, deposit wallets, sweep targets, treasury EOAs, fee payers), queried against your own archive or full node, or a chain indexer you trust. Lookback: since the chain activated EIP-7702, or at least 90 days.

**Data quality check first.** You need an archive node (for historical `eth_getCode` at a block) or an indexer that exposes transaction `type` and `authorizationList`. Confirm your node returns `"type":"0x4"` and an `authorizationList` array in `eth_getTransactionByHash` for a known type-4 transaction before trusting a negative.

## Execute

1. **Current state.** For each owned EOA, call `eth_getCode` at `latest`. A plain EOA returns `0x`. A delegated EOA returns `0xef0100` plus 40 hex characters (the delegate address), 23 bytes in total. Any owned EOA with non-empty code that you did not deliberately delegate is a P1 finding.
2. **History.** Repeat `eth_getCode` at historical blocks (archive node), or scan blocks for transactions with `type == 0x4` and recover the authority of each authorization tuple (`chainId`, `address`, `nonce`, `yParity`, `r`, `s`) with your signing library; flag any tuple whose authority is one of your EOAs, whether or not it was applied. An invalid tuple (wrong nonce, wrong chain) is skipped without reverting the transaction, so failed attempts remain visible as tuples in mined transactions.
3. **Nonce anomalies.** An authorization consumes the authority's nonce when applied. Compare each owned EOA's nonce history with your signing-service ledger: nonces your signer did not issue are a finding.
4. **Delegate review.** For any delegate found, fetch its code and ask: is it a contract your wallet team deployed and audited, is it on your allowlist, does it expose an entry point that moves full balances to a fixed address.

```bash
# Author: Jarmi
# Read-only, against your own node. Replace <OWN_NODE_RPC> and <OWNED_EOA>. Requires curl and jq.
RPC="<OWN_NODE_RPC>"     # e.g. http://127.0.0.1:8545 on the node host
ADDR="<OWNED_EOA>"
CODE=$(curl -s -X POST -H 'Content-Type: application/json' \
  --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getCode\",\"params\":[\"$ADDR\",\"latest\"]}" "$RPC" | jq -r .result)
case "$CODE" in
  0x)          echo "$ADDR plain EOA, no delegation" ;;
  0xef0100*)   echo "$ADDR DELEGATED to 0x${CODE:8:40} - verify against the wallet-team allowlist" ;;
  *)           echo "$ADDR has non-delegation code (contract account?) - check inventory" ;;
esac
# List type-4 transactions in one block (repeat over a range). Replace <BLOCK_HEX>.
curl -s -X POST -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["<BLOCK_HEX>",true]}' "$RPC" | \
  jq -c '.result.transactions[] | select(.type=="0x4") | {hash, from, to, n_auth: (.authorizationList|length), auth: [.authorizationList[] | {address, nonce, chainId}]}'
```

**Expected benign.** A delegate your wallet or account-abstraction team deployed deliberately (batching, gas sponsorship, smart-account features), documented in change records, with audited code and an allowlisted delegate address. Customer EOAs delegating to public smart-account implementations are normal and out of scope; only your own addresses matter here. Benign type-4 transactions carry one or a few tuples, not dozens with consecutive nonces.

## Act

- **Positive (unplanned delegate on an owned EOA, or tuples recovering to an owned EOA that your signer did not create):** treat it as active fund loss in progress. Stop deposit-sweep jobs that refill that EOA, move remaining balances through a clean signer to fresh addresses, revoke the delegation (a new authorization to the zero address from the legitimate key, if the key is trusted), notify stablecoin issuers and analytics partners for freezes, and preserve node logs and signer audit trails. Then run H1 and H3.
- **Negative:** schedule `eth_getCode` on all owned EOAs every block or every minute, alert on any non-`0x` result that is not allowlisted, and have the signing service refuse to produce EIP-7702 authorizations unless an explicit, separately approved policy allows it.
- **Escalate** to custody / treasury owners and the incident commander immediately; this is a funds-at-risk signal, not a SOC ticket.

## Knowledge

Record the owned-EOA inventory, allowlisted delegates, the polling job and the signer policy. Related: [Suricata](../suricata/binance_devops_egress.rules) sid 9800001 (transaction submission from non-signer hosts), [YARA](../yara/binance_devops_workstation_artifacts.yar) rule `Generic_Solidity_Sweeper_Delegate_Source_Pattern` (sweeper-shaped source text).
