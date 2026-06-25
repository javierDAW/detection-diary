// Miasma Dead-Drop C2 Marker Strings in JavaScript Payloads
// Author: Jarmi
// Date: 2026-06-25
// Reference: https://www.aikido.dev/blog/compromised-github-action-codfish-steals-secrets
// Reference: https://safedep.io/inside-the-miasma-supply-chain-attack-toolkit/
// Confidence: high (exact strings from toolkit analysis and Aikido disclosure)
// Family: Miasma (Shai-Hulud lineage)
// Note: These marker strings are the dead-drop C2 channel keys embedded in Miasma
// payloads. The strings are searched via the GitHub public commit search API.
// All three markers should be hunted; each corresponds to a different capability
// module in the leaked toolkit.

rule Miasma_DeadDrop_JS_Marker_TheBeautifulSandsOfTime {
    meta:
        author = "Jarmi"
        description = "Detects Miasma JS variant dead-drop marker for JavaScript payload delivery channel"
        date = "2026-06-25"
        reference = "https://www.aikido.dev/blog/compromised-github-action-codfish-steals-secrets"
        confidence = "high"
        family = "Miasma"
    strings:
        $marker_exact = "thebeautifulsnadsoftime" ascii nocase
        $marker_camel = "TheBeautifulSandsOfTime" ascii
        $obf_pattern = "_0x" ascii
        $bun_ref = "GITHUB_ACTION_PATH" ascii
    condition:
        filesize < 5MB
        and ($marker_exact or $marker_camel)
        and ($obf_pattern or $bun_ref)
}

rule Miasma_DeadDrop_PAT_Exfil_Marker {
    meta:
        author = "Jarmi"
        description = "Detects Miasma PAT exfiltration dead-drop channel marker"
        date = "2026-06-25"
        reference = "https://safedep.io/inside-the-miasma-supply-chain-attack-toolkit/"
        confidence = "high"
        family = "Miasma"
    strings:
        $pat_marker = "DontRevokeOrItGoesBoom" ascii
        $github_search = "api.github.com/search/commits" ascii
    condition:
        filesize < 5MB
        and ($pat_marker or $github_search)
}

rule Miasma_Hades_Python_DeadDrop_Marker {
    meta:
        author = "Jarmi"
        description = "Detects Miasma Hades Python variant dead-drop channel marker (firedalazer)"
        date = "2026-06-25"
        reference = "https://phoenix.security/miasma-azure-hades-pypi-supply-chain-worm-2026/"
        confidence = "high"
        family = "Miasma-Hades"
    strings:
        $hades_marker = "firedalazer" ascii
        $spreading_blight = "Miasma: The Spreading Blight" ascii
        $search_api = "/search/commits?q=" ascii
    condition:
        filesize < 10MB
        and ($hades_marker or $spreading_blight or $search_api)
}
