rule ShaiHulud_ThirdComing_BunLoader_Heuristic
{
    meta:
        author       = "Jarmi"
        description  = "Heuristic for the 'Shai-Hulud: The Third Coming' Bun loader (bw_setup.js / bw1.js): single-line minified JS with credential-target list (cloud + CI + AI CLIs) and dead-drop GitHub exfil"
        date         = "2026-04-29"
        reference    = "https://research.jfrog.com/"
        confidence   = "medium-high (heuristic — string-anchored)"
        family       = "Shai-Hulud"

    strings:
        // Marker / branding
        $marker1 = "Shai-Hulud" ascii nocase
        $marker2 = "Third Coming" ascii nocase
        $marker3 = "audit.checkmarx" ascii nocase

        // Credential-target paths — cloud + CI + AI CLI (the new bit)
        $tgt_aws    = ".aws/credentials" ascii
        $tgt_aws2   = ".aws/config" ascii
        $tgt_gcp    = "application_default_credentials.json" ascii
        $tgt_gcp2   = ".config/gcloud/" ascii
        $tgt_az     = ".azure/" ascii
        $tgt_npm    = ".npmrc" ascii
        $tgt_gh     = ".gitconfig" ascii
        $tgt_ssh    = ".ssh/id_" ascii
        $tgt_claude = ".claude" ascii nocase
        $tgt_codex  = ".codex" ascii nocase
        $tgt_cursor = ".cursor" ascii nocase
        $tgt_gemini = "gemini-cli" ascii nocase

        // Bun-specific runtime fingerprints
        $bun_runtime = "Bun.spawn" ascii
        $bun_runtime2 = "Bun.write" ascii
        $bun_runtime3 = "import.meta.resolveSync" ascii

        // GitHub dead-drop API
        $gh_repo_api = "api.github.com/user/repos" ascii
        $gh_token    = "Authorization: token " ascii

    condition:
        filesize < 12MB and
        (
          any of ($marker*) or
          (
            (any of ($bun_runtime*) or $gh_repo_api or $gh_token) and
            5 of ($tgt_*)
          )
        )
}
