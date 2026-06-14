# PEAK Hunt H1 — Hancom-signed binary on a crypto-treasury endpoint

**Author:** Jarmi
**Date:** 2026-06-14
**Case:** Humanity Protocol $36M bridge takeover (DPRK-linked, Quantstamp)
**Type:** Hypothesis-driven (PEAK)

## Hypothesis

A DPRK-linked operator runs a remote-access loader signed with a stolen/forged South Korean **Hancom** code-signing certificate to gain trust and evade reputation/app-control checks. If that activity occurred (or recurs) in our estate, a signer/treasury/developer endpoint with **no Korean-office software footprint** executed or loaded a binary whose signer subject contains `Hancom`.

## ABLE framing

- **Actor:** DPRK-linked intrusion set (Lazarus/TraderTraitor-class crypto targeting).
- **Behaviour:** code-signing trust abuse (T1553.002) using an obtained certificate (T1588.003).
- **Location:** crypto signer / treasury / developer endpoints; image-load and process-create telemetry; the Authenticode signer field.
- **Evidence:** `DeviceImageLoadEvents.Signer` / `DeviceProcessEvents.Signer` containing `Hancom`; `Get-AuthenticodeSignature` subject.

## Data sources

- Defender XDR `DeviceImageLoadEvents`, `DeviceProcessEvents` (Signer / CertificateSubject).
- Sysmon EID 7 (image load) with signature subject enrichment.
- Asset inventory (which hosts legitimately run Hancom Office).

## Query seed

See [../kql/humanity_hancom_signed_loader.kql](../kql/humanity_hancom_signed_loader.kql) and [../sigma/hancom_signed_binary_on_crypto_endpoint.yml](../sigma/hancom_signed_binary_on_crypto_endpoint.yml).

```kql
DeviceImageLoadEvents
| where Timestamp > ago(45d)
| where Signer has "Hancom" or CertificateSubject has "Hancom"
| summarize hosts=make_set(DeviceName,50), files=make_set(FileName,50) by Signer
```

## Triage / pivots

1. Cross-reference matched hosts against the asset inventory — exclude genuine Korean-office machines.
2. For surviving hits, pull the cert serial/thumbprint and validity; an invalid/expired/mismatched signature sharply raises confidence.
3. Pivot the binary hash and path to `DeviceProcessEvents` for child processes (remote-access tooling, keystore access).
4. Check the host for the H2 keystore-access pattern within the same session window.

## Outcome / ABLE close

- **Found:** isolate the host, treat any keys on it as burned, escalate to the IR playbook.
- **Not found:** record the certificate-anomaly hunt as coverage; convert the seed to a scheduled analytic scoped to crypto/treasury asset groups.
