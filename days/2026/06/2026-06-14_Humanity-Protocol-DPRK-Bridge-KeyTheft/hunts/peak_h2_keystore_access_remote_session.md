# PEAK Hunt H2 — Wallet/keystore file access during a remote-access session

**Author:** Jarmi
**Date:** 2026-06-14
**Case:** Humanity Protocol $36M bridge takeover (DPRK-linked, Quantstamp)
**Type:** Hypothesis-driven (PEAK)

## Hypothesis

After gaining hands-on-keyboard remote control of a signer's device, the operator reads wallet key material from disk (keystore JSON, `UTC--` files, `wallet.dat`, MetaMask vault, seed/mnemonic files) using a process that is **not** a wallet application. If this happened, we will see keystore/seed file access by a non-wallet process, ideally overlapping an active interactive remote-desktop session.

## ABLE framing

- **Actor:** DPRK-linked operator with remote-desktop control.
- **Behaviour:** unsecured-credentials-in-files / credentials-from-stores (T1552.001, T1555), data from local system (T1005).
- **Location:** signer/treasury endpoints; file-event telemetry; wallet/keystore directories.
- **Evidence:** `DeviceFileEvents` on wallet paths where the initiating process is not a known wallet/backup app; concurrent remote-access process/network activity.

## Data sources

- Defender XDR `DeviceFileEvents` (FileAccessed/Modified).
- `DeviceProcessEvents` / `DeviceNetworkEvents` for the concurrent remote-access session.
- Sysmon EID 11 (file) + EID 1/3 (process/network).

## Query seed

See [../kql/humanity_wallet_keystore_access.kql](../kql/humanity_wallet_keystore_access.kql) and [../sigma/wallet_keystore_access_by_nonwallet_process.yml](../sigma/wallet_keystore_access_by_nonwallet_process.yml).

```kql
let walletPaths = dynamic(["keystore","UTC--","wallet.dat","MetaMask","mnemonic","seed.txt"]);
DeviceFileEvents
| where Timestamp > ago(14d)
| where FolderPath has_any (walletPaths) or FileName has_any (walletPaths)
| where InitiatingProcessFileName !in~ ("MetaMask.exe","Ledger Live.exe","Exodus.exe","MsMpEng.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, FolderPath, FileName, InitiatingProcessAccountName
```

## Triage / pivots

1. For each hit, check whether a remote-access tool (AnyDesk/RustDesk/TeamViewer/VNC/mstsc) was active on the host in the same window.
2. Identify which key material was read (which Safe signer, which chain) to scope the on-chain blast radius.
3. Pivot to H3 to check for a subsequent on-chain ProxyAdmin/owner change from that signer set.
4. Confirm the initiating binary is not a sanctioned backup/AV agent before escalating.

## Outcome / ABLE close

- **Found:** assume the read keys are compromised; trigger Safe owner rotation on every affected chain and isolate the host.
- **Not found:** keep as detection coverage; ensure wallet/keystore paths are in the file-audit scope on all signer endpoints.
