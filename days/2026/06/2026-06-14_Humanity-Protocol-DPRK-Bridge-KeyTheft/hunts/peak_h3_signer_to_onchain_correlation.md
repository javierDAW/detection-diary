# PEAK Hunt H3 — Signer-endpoint compromise correlated to an on-chain admin change

**Author:** Jarmi
**Date:** 2026-06-14
**Case:** Humanity Protocol $36M bridge takeover (DPRK-linked, Quantstamp)
**Type:** Hypothesis-driven (PEAK), cross-domain (SOC + on-chain)

## Hypothesis

The defensible window in a key-theft bridge takeover is the few hours between **endpoint compromise of a Safe signer** and the **on-chain admin change** (ProxyAdmin `transferOwnership`, proxy `upgradeTo`/`upgradeAndCall`, owner-set change, or abnormal mint). If an endpoint alert fires on a host that holds Gnosis Safe signer keys, we should be able to correlate it — within hours — to admin-level activity on the chains that signer governs. This hunt builds that bridge.

## ABLE framing

- **Actor:** DPRK-linked operator using stolen valid keys (T1078).
- **Behaviour:** valid-account on-chain admin takeover and financial theft (T1657) following endpoint key theft.
- **Location:** the seam between host telemetry (EDR) and on-chain monitoring (block explorers / Tenderly / Forta-style alerts).
- **Evidence:** an endpoint alert on a signer host, followed by `transferOwnership` / proxy upgrade / owner change / large mint from the signer's Safe set.

## Data sources

- EDR alerts/timeline for hosts mapped to Safe signers (maintain a signer→host→Safe→chain inventory).
- On-chain monitoring for every Safe/ProxyAdmin the org controls: ownership transfers, implementation upgrades, owner add/remove, threshold change, abnormal mint/withdraw.
- Block explorers (Etherscan/BscScan), Tenderly/Forta or equivalent admin-event alerting.

## Procedure

1. Maintain a mapping: each Safe signer key → the device(s) it is used from → the Safes it owns → the ProxyAdmins those Safes control → the chains.
2. When any signer host raises an endpoint alert (H1 Hancom cert, H2 keystore access, RAT activity), immediately query on-chain monitoring for admin events on that signer's Safes for the next 24–72h.
3. Conversely, any unscheduled `transferOwnership`/`upgrade`/owner-change on a watched ProxyAdmin should trigger an immediate endpoint review of every signer of that Safe.
4. Treat simultaneous activity across multiple chains as a strong signal of a pre-staged operator (this case hit Ethereum and BSC in parallel).

## Triage / pivots

- Pull the on-chain tx hashes (ownership transfer + upgrade) and the new implementation address; flag the attacker wallet and tainted tokens on a public tracker.
- Determine which chains are recoverable (uncompromised Safe still in control) vs. lost (attacker owns ProxyAdmin) to prioritise freeze vs. abandon.

## Outcome / ABLE close

- **Found correlation:** execute freeze/pause via any uncompromised authority, rotate Safe owners, notify exchanges/LE.
- **No correlation infrastructure yet:** the deliverable of this hunt is the signer→Safe→chain inventory plus the bidirectional alert wiring; stand it up so the next signer-endpoint alert is correlated to chain activity in minutes, not after the funds are gone.
