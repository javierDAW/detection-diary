# Hunt H3 — Kernel callback baseline drift (ELAM-style ground truth)

## Hypothesis

Stage 4 of the Qilin / Warlock loader unregisters EDR kernel callbacks (such as `cng!CngCreateProcessNotifyRoutine`) by walking the slot table for `PsSetCreateProcessNotifyRoutineEx`, `PsSetCreateThreadNotifyRoutine` and `PsSetLoadImageNotifyRoutine` and overwriting the function pointers via direct physical-memory writes. A lightweight kernel-mode agent that periodically enumerates the registered callbacks against a known-good baseline can flag the disappearance of an expected EDR callback in real time.

## Why this discriminates

- Legitimate kernel callbacks register at boot and persist for the host's session unless the EDR product is uninstalled or reboots the system.
- A callback disappearing during a live session, without a reboot, is structurally a near-zero-FP signal of either an EDR malfunction or a deliberate unregistration by an attacker.

## Expected benign vs malicious

- **Benign:** scheduled EDR self-update that triggers a callback re-registration window of a few seconds; immediately followed by re-registration.
- **Malicious:** the EDR callback is unregistered and stays unregistered, with the host still active on the network.

## Action on match

1. Network-isolate the host immediately.
2. Pull a kernel-mode memory dump (full RAM, not user-mode minidump).
3. Compare with the host's known callback baseline.
4. Hunt across the fleet for hosts loaded with the same driver hashes (`rwdrv.sys`, `hlpdrv.sys`).

## Implementation hint — minimal callback enumeration

Most enterprise EDRs already expose this telemetry. If you do not have it, lightweight open-source kernel-mode tools (for example `PsSetCreateProcessNotifyRoutine` enumerators in projects like SwishDbgExt, WinDbg `!process` extensions or Volatility 3 plugins on a memory image) can establish a baseline and flag drift.

## Reference

- [Qilin EDR killer infection chain — Cisco Talos](https://blog.talosintelligence.com/qilin-edr-killer/)
