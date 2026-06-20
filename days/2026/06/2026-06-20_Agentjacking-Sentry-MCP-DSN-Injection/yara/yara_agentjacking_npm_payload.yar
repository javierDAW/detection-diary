/*
 * YARA rules for Agentjacking npm payload detection
 * Case: Agentjacking via Sentry MCP DSN Injection (Tenet Security, June 2026)
 * Reference: https://tenetsecurity.ai/blog/agentjacking-coding-agents-with-fake-sentry-errors/
 * Author: Jarmi
 * Date: 2026-06-20
 *
 * Targets:
 *   rule 1 — npm package JS files containing the Sentry resolution injection pattern
 *   rule 2 — npm package files probing developer credential paths (AWS + npm + Docker)
 *   rule 3 — Sentry ingest POST body with embedded shell command in resolution field
 *
 * Apply to:
 *   - ~/.npm/_npx/ cache directories (one-off npx packages)
 *   - npm package tarballs (.tgz) from threat intel feeds
 *   - HTTP request captures to *.ingest.sentry.io
 */

rule Agentjacking_Npm_Resolution_Injection {
    meta:
        author = "Jarmi"
        description = "Detects npm package JS code containing markdown resolution-injection patterns targeting AI coding agent context windows via Sentry MCP"
        date = "2026-06-20"
        reference = "https://tenetsecurity.ai/blog/agentjacking-coding-agents-with-fake-sentry-errors/"
        confidence = "medium"
        family = "Agentjacking"

    strings:
        // Markdown ## Resolution heading used to inject into agent context
        $resolution_header = "## Resolution" ascii wide nocase
        // npx with auto-accept in a string or template literal
        $npx_yes = "npx --yes" ascii wide
        $npx_y = "npx -y " ascii wide
        // Sentry ingest endpoint reference in package code
        $sentry_ingest = "ingest.sentry.io" ascii wide
        // Common payload delivery via extra.resolution key
        $extra_resolution = "extra" ascii wide
        $resolution_key = "\"resolution\"" ascii wide

    condition:
        filesize < 512KB and
        (($resolution_header and ($npx_yes or $npx_y)) or
        ($sentry_ingest and $extra_resolution and $resolution_key and ($npx_yes or $npx_y)))
}

rule Agentjacking_Npm_Credential_Probe {
    meta:
        author = "Jarmi"
        description = "Detects npm package code containing AWS credential paths plus npm and Docker credential files alongside an HTTP POST beacon — consistent with the Agentjacking PoC credential harvest and exfiltration stage"
        date = "2026-06-20"
        reference = "https://tenetsecurity.ai/blog/agentjacking-coding-agents-with-fake-sentry-errors/"
        confidence = "medium"
        family = "Agentjacking"

    strings:
        // AWS credential paths
        $aws_config = ".aws/config" ascii wide
        $aws_creds = ".aws/credentials" ascii wide
        // npm auth token
        $npmrc = ".npmrc" ascii wide
        // Docker credentials
        $docker_cfg = ".docker/config.json" ascii wide
        // Beacon exfiltration pattern (HTTP POST with collected data)
        $https_post = "https.request" ascii wide
        $fetch_post = "fetch(" ascii wide

    condition:
        filesize < 512KB and
        (($aws_config or $aws_creds) and $npmrc and $docker_cfg) and
        ($https_post or $fetch_post)
}

rule Agentjacking_Sentry_Ingest_Payload {
    meta:
        author = "Jarmi"
        description = "Detects HTTP request bodies destined for Sentry ingest endpoints containing shell command injection in resolution or extra fields — matches network capture or proxy log artifacts"
        date = "2026-06-20"
        reference = "https://tenetsecurity.ai/blog/agentjacking-coding-agents-with-fake-sentry-errors/"
        confidence = "high"
        family = "Agentjacking"

    strings:
        // Sentry ingest target in HTTP body or capture
        $sentry_ingest_host = "ingest.sentry.io" ascii wide
        // Injected resolution section
        $res_header_md = "## Resolution" ascii wide nocase
        // Shell execution vectors in JSON string context
        $npx_shell = "npx " ascii wide
        $curl_cmd = "curl " ascii wide
        $wget_cmd = "wget " ascii wide
        $bash_cmd = "bash -c" ascii wide nocase
        // X-Sentry-Auth header pattern
        $sentry_auth = "X-Sentry-Auth" ascii wide nocase

    condition:
        filesize < 128KB and
        $sentry_ingest_host and
        $res_header_md and
        ($npx_shell or $curl_cmd or $wget_cmd or $bash_cmd) and
        $sentry_auth
}
