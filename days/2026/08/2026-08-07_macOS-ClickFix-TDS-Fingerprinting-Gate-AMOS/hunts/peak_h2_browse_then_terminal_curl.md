# PEAK hunt H2 -- Browse-then-Terminal curl chain

**Hypothesis.** A ClickFix victim runs a pasted one-liner shortly after web browsing, so an endpoint that browses the web and then spawns `curl` piped into a shell -- especially retrieving a `/curl/<hex>` path -- is executing the ClickFix chain.

**Prepare.** Scope to macOS endpoints with process telemetry (`DeviceProcessEvents`, ESF, or osquery `process_events`). Look back 14 days.

**Execute.**
- Find `curl` processes whose command line contains `/curl/` or a pipe into `zsh`/`sh`/`bash`.
- Prioritise those whose initiating/parent process is `Terminal`, a shell, or a browser-descended process.
- Correlate with a web/proxy or DNS event to a flagged front-end domain on the same host in the minutes prior.

**Analyze.** Triage the parent lineage and the retrieved URL. A `/curl/<hex>` retrieval piped to a shell from an interactive Terminal is confirmed execution; a bare network hit to a front-end domain is not (it may be a gated/decoy response).

**Know.** Promote the confirmed chain to a detection; record the staging host for blocking. Assume credential compromise if the chain completed.

Related: `../sigma/02_macos_clickfix_native_tool_sequence.yml`, `../kql/k1_macos_curl_pipe_shell.kql`, `../kql/k2_macos_clickfix_domains_network.kql`.
