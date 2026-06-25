// Miasma Malicious Composite GitHub Action Pattern Detection
// Author: Jarmi
// Date: 2026-06-25
// Reference: https://www.aikido.dev/blog/compromised-github-action-codfish-steals-secrets
// Confidence: medium (heuristic — pattern matches malicious composite structure)
// Family: Miasma
// Note: This rule targets action.yml files that combine the three elements of the
// Miasma malicious composite pattern: setup-bun installation, if-always gating bypass,
// and bun run from GITHUB_ACTION_PATH. Benign composites that use Bun legitimately
// are unlikely to combine all three patterns without a declared project need.

rule Miasma_Malicious_Composite_ActionYML {
    meta:
        author = "Jarmi"
        description = "Detects action.yml with Miasma-style composite: setup-bun + if-always + bun run GITHUB_ACTION_PATH"
        date = "2026-06-25"
        reference = "https://www.aikido.dev/blog/compromised-github-action-codfish-steals-secrets"
        confidence = "medium"
        family = "Miasma"
    strings:
        $setup_bun = "oven-sh/setup-bun" ascii
        $if_always_1 = "if: always()" ascii
        $if_always_2 = "if: ${{ always() }}" ascii
        $bun_run = "bun run" ascii
        $gha_path = "GITHUB_ACTION_PATH" ascii
        $composite = "using: composite" ascii
    condition:
        filesize < 50KB
        and $setup_bun
        and ($if_always_1 or $if_always_2)
        and $bun_run
        and $gha_path
        and $composite
}

rule Miasma_Large_Obfuscated_JS_In_Action_Repo {
    meta:
        author = "Jarmi"
        description = "Large obfuscated JS file (>500KB) with _0x hex variable pattern in a GitHub Action context"
        date = "2026-06-25"
        reference = "https://www.aikido.dev/blog/compromised-github-action-codfish-steals-secrets"
        confidence = "medium"
        family = "Miasma"
    strings:
        $obf_array_init = "_0x" ascii
        $hex_var1 = "const _0x" ascii
        $hex_var2 = "var _0x" ascii
        $eval_call = "eval(" ascii
    condition:
        filesize > 500KB
        and filesize < 5MB
        and ($hex_var1 or $hex_var2)
        and $obf_array_init
        and $eval_call
}
