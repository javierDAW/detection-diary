# H3 -- Hidden .zx_ staging archive followed by a libcurl exfil POST

## Frame

Prepare-Execute-Act-Know hunt. CrashStealer encrypts each collected item with AES-256-GCM,
zips the results into hidden archives named `.zx_` plus eight random hex characters under
`~/.cache/com.apple.crashreporter/`, then removes its staging directories but leaves the
`.zx_*.zip` archives behind -- a durable filesystem artifact even after the process exits or
is killed. Exfiltration happens over `libcurl` to attacker infrastructure shortly after the
archive is created.

## Hypothesis

If CrashStealer-class exfiltration completed on a host, a hidden `.zx_*.zip` archive will
exist (or will have existed, per file-system journal / USN-equivalent artifacts) under
`~/.cache/`, and a `libcurl`-linked process will have made an outbound POST to a young or
previously-unseen domain within a short window of that archive's creation timestamp.

## Expected benign baseline

Near zero for the specific `.zx_` naming pattern -- it is not a convention used by any known
legitimate macOS software. The looser signal (a hidden zip under `~/.cache/` generally) has
some legitimate baseline from application caching behavior, so anchor primarily on the exact
`.zx_` prefix plus the timing correlation with outbound network activity, not on hidden
archives in `~/.cache/` alone.

## Action on match

Recover the archive if still present for offline analysis (do not attempt to decrypt without
the operator's key material -- treat its mere existence and size as sufficient evidence of
scope), identify the destination host/IP of the correlated network connection and check it
against this case's IOC list and any subsequently published CrashStealer infrastructure,
and, if the destination is not yet a known indicator, submit it for passive-DNS and
threat-intel triangulation before assuming it is unrelated.
