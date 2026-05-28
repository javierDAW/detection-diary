/*
   YARA rules — TrapDoor cross-ecosystem crypto / AI-developer credential stealer
   Author:      Jarmi
   Date:        2026-05-28
   Family:      TrapDoor (Socket-tracked, unattributed e-crime cluster)
   References:
     - https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates
     - https://thehackernews.com/2026/05/trapdoor-supply-chain-attack-spreads.html
     - https://phoenix.security/trapdoor-supply-chain-ai-poisoning-npm-pypi-crates/

   Coverage:
     - rule trapdoor_npm_trap_core_js   shared trap-core.js heuristic (size + persistence + cipher + validator anchors).
     - rule trapdoor_pypi_node_e_remote PyPI auto-import that spawns node -e against attacker GitHub Pages.
     - rule trapdoor_crates_build_rs_xor Cargo build.rs that exfiltrates Sui/Move keystores via GitHub Gists with hardcoded XOR.
     - rule trapdoor_ai_config_zwsp     .cursorrules / CLAUDE.md carrying zero-width Unicode prompt-injection markers.
*/

rule trapdoor_npm_trap_core_js
{
    meta:
        author      = "Jarmi"
        date        = "2026-05-28"
        description = "TrapDoor shared npm payload trap-core.js, credential harvester and propagation tool"
        reference   = "https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates"
        family      = "TrapDoor"
        confidence  = "high"

    strings:
        $name_trap_core   = "trap-core.js" ascii nocase
        $marker_campaign  = "P-2024-001" ascii
        $persist_cursor   = ".cursorrules" ascii
        $persist_claude   = "CLAUDE.md" ascii
        $persist_git      = "githooks" ascii nocase
        $persist_systemd  = "/etc/systemd/system" ascii
        $persist_cron     = "crontab" ascii nocase
        $persist_ssh      = "authorized_keys" ascii
        $cipher_fernet    = "fernet" ascii nocase
        $cipher_ecdh      = "ECDH" ascii
        $validate_aws     = "sts.amazonaws.com" ascii
        $validate_github  = "api.github.com/user" ascii
        $url_attacker     = "ddjidd564.github.io" ascii nocase
        $url_attacker2    = "defi-security-best-practices" ascii nocase

    condition:
        filesize < 1MB
        and (
            ($name_trap_core and $marker_campaign)
            or (2 of ($persist_cursor, $persist_claude, $persist_git, $persist_systemd, $persist_cron, $persist_ssh)
                and ($cipher_fernet or $cipher_ecdh)
                and ($validate_aws or $validate_github))
            or ($url_attacker and ($persist_cursor or $persist_claude))
            or ($url_attacker2 and ($cipher_fernet or $cipher_ecdh))
        )
}

rule trapdoor_pypi_node_e_remote
{
    meta:
        author      = "Jarmi"
        date        = "2026-05-28"
        description = "TrapDoor PyPI package auto-import that delegates execution to remote JavaScript via node -e"
        reference   = "https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates"
        family      = "TrapDoor"
        confidence  = "high"

    strings:
        $node_dash_e   = "node -e" ascii
        $node_dash_e2  = "node('-e'" ascii
        $url_attacker  = "ddjidd564.github.io" ascii nocase
        $url_attacker2 = "defi-security-best-practices" ascii nocase
        $subproc       = "subprocess" ascii
        $urllib        = "urllib" ascii
        $requests      = "requests.get" ascii
        $py_setup      = "setup(" ascii
        $py_import     = "__init__" ascii
        $py_eval       = "eval(" ascii

    condition:
        filesize < 256KB
        and ($node_dash_e or $node_dash_e2)
        and ($url_attacker or $url_attacker2)
        and ($subproc or $urllib or $requests or $py_eval)
        and ($py_setup or $py_import)
}

rule trapdoor_crates_build_rs_xor
{
    meta:
        author      = "Jarmi"
        date        = "2026-05-28"
        description = "TrapDoor Cargo build.rs that exfiltrates Sui/Move keystores using hardcoded XOR key"
        reference   = "https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates"
        family      = "TrapDoor"
        confidence  = "high"

    strings:
        $xor_key      = "cargo-build-helper-2026" ascii
        $sui          = ".sui/keystore" ascii
        $move         = "move/keys" ascii nocase
        $gist         = "gist.githubusercontent.com" ascii
        $build_main   = "fn main" ascii
        $rs_xor_loop  = "^=" ascii
        $rs_reqwest   = "reqwest" ascii
        $rs_std_env   = "std::env" ascii

    condition:
        filesize < 128KB
        and (
            $xor_key
            or (($sui or $move) and $gist and $build_main)
            or ($rs_xor_loop and $gist and ($sui or $move))
        )
        and ($rs_reqwest or $rs_std_env)
}

rule trapdoor_ai_config_zwsp
{
    meta:
        author      = "Jarmi"
        date        = "2026-05-28"
        description = "TrapDoor .cursorrules / CLAUDE.md that hides instructions using zero-width Unicode characters"
        reference   = "https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates"
        family      = "TrapDoor"
        confidence  = "medium"

    strings:
        $zwsp     = { E2 80 8B }
        $zwnj     = { E2 80 8C }
        $zwj      = { E2 80 8D }
        $bom      = { EF BB BF }
        $marker_p = "P-2024-001" ascii
        $cfg_url  = "ddjidd564.github.io" ascii nocase
        $sec_scan = "security scan" ascii nocase
        $audit    = "AUDIT-MATRIX" ascii nocase

    condition:
        filesize < 64KB
        and 2 of ($zwsp, $zwnj, $zwj, $bom)
        and ($marker_p or $cfg_url or $sec_scan or $audit)
}
