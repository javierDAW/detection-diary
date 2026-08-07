# PEAK hunt H1 -- Hunt the fingerprinting gate, not the payload

**Hypothesis.** Because delivery is restricted to qualified macOS visitors, the downstream AMOS/MacSync payloads are rarely observed and rotate, but the TDS gate is served in the clear to any collector that reads page bodies without executing JavaScript. Malicious front-end domains in our web/proxy telemetry will therefore expose gate artifacts even when they never serve us the lure.

**Prepare.** Scope to outbound web traffic and any URL-inspection/crawler store that captures response bodies. Pull newly seen or low-reputation domains from the last 14-30 days.

**Execute.** Pivot on combinations, not single strings (these primitives also appear in legitimate anti-bot systems):
- Response body contains a self-submitting fingerprint form and hidden fingerprint fields.
- The `mode:"php"` submission tag.
- A small (~2.5 KB) script that reads `navigator.platform` (`MacIntel`), enumerates `screen`/`window`, runs a WebGL renderer probe (`WEBGL_debug_renderer_info` / `UNMASKED_RENDERER_WEBGL`), and checks `getTimezoneOffset`, iframe context, and `ontouchstart`.
- The `canPlayType("video/mp4")` prototype tripwire and/or a devtools `toString()` counter.
- Domain shape: `file<word><word>` (e.g. `filecopperbasket[.]sbs`) or `<word>file<word>` / `<word><word>file`.

**Analyze.** Rank domains by how many independent signals co-occur. A domain hitting the gate-JS artifacts plus the naming shape plus shared staging behaviour is high-confidence even if it only ever returned a blank/decoy page to us.

**Know.** Feed confirmed staging hosts and `/curl/` paths to blocking; capture the co-occurrence logic as a scheduled analytic. Note that a benign/decoy response is not evidence the domain is safe.

Related: `../sigma/01_macos_terminal_curl_pipe_shell.yml`, `../yara/clickfix_macos_tds_gate.yar`.
