/*
 * Rule:      MiniShaiHulud_TransformersPyz_TeamPCP_2026
 * Author:    Jarmi
 * Date:      2026-05-14
 * Reference: https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised
 * Description:
 *   Detects the TeamPCP Mini Shai-Hulud transformers.pyz credential-stealer
 *   Python zipapp distributed via compromised npm/PyPI packages (May 2026).
 *   Targets developer machines. Harvests 100+ credential paths (cloud, crypto,
 *   password vaults, CI/CD). Exits on Russian locale or CPU count < 4.
 */

rule MiniShaiHulud_TransformersPyz_TeamPCP_2026 {
    meta:
        author      = "Jarmi"
        description = "TeamPCP Mini Shai-Hulud transformers.pyz credential-stealer Python zipapp (May 2026). First documented campaign targeting 1Password and Bitwarden local vaults alongside cloud and crypto credentials."
        date        = "2026-05-14"
        reference   = "https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised"
        confidence  = "high"
        family      = "MiniShaiHulud"

    strings:
        $zip_magic    = { 50 4B 03 04 }
        $main_entry   = "__main__.py" ascii
        $hash_anchor  = "ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c" ascii
        $c2_primary   = "83.142.209." ascii
        $c2_domain    = "git-tanstack" ascii
        $c2_session   = "getsession.org" ascii
        $cred_eth     = ".ethereum/keystore" ascii
        $cred_foundry = ".foundry/keystores" ascii
        $cred_1pw     = "1Password" ascii
        $cred_brownie = ".brownie/accounts" ascii
        $guardrail    = "cpu_count() < 4" ascii

    condition:
        $zip_magic at 0
        and $main_entry
        and ($hash_anchor or $c2_primary or $c2_domain or $c2_session or $guardrail)
        and 2 of ($cred_eth, $cred_foundry, $cred_1pw, $cred_brownie)
        and filesize < 20MB
}


rule MiniShaiHulud_GhTokenMonitor_Daemon_2026 {
    meta:
        author      = "Jarmi"
        description = "Detects the gh-token-monitor persistence daemon installed by Mini Shai-Hulud (TeamPCP, May 2026). Polls GitHub every 60s using a stolen token and triggers a destructive command on token revocation (HTTP 40x). Auto-exits after 24h if not triggered."
        date        = "2026-05-14"
        reference   = "https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem"
        confidence  = "high"
        family      = "MiniShaiHulud"

    strings:
        $svc_name1 = "gh-token-monitor" ascii wide
        $svc_name2 = "com.github.token-monitor" ascii wide
        $destruct1 = "rm -rf ~/" ascii
        $destruct2 = "rm -rf" ascii
        $poll_str  = "github.com" ascii
        $plist_key = "RunAtLoad" ascii

    condition:
        ($svc_name1 or $svc_name2)
        and ($destruct1 or $destruct2 or ($poll_str and $plist_key))
}
