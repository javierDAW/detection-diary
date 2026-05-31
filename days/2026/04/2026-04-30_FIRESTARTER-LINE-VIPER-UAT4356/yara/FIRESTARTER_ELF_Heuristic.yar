rule FIRESTARTER_ELF_LINA_Hook_Heuristic
{
    meta:
        author       = "Jarmi"
        description  = "Heuristic for FIRESTARTER ELF (UAT-4356 / Storm-1849 / ArcaneDoor) targeting Cisco ASA LINA + CSP_MOUNT_LIST persistence string"
        date         = "2026-04-30"
        reference    = "https://www.cisa.gov/news-events/cybersecurity-advisories/"
        confidence   = "medium-high (heuristic)"
        family       = "FIRESTARTER"

    strings:
        // ASA platform-specific paths and symbols
        $p_mount     = "CSP_MOUNT_LIST" ascii
        $p_rmdb      = "/opt/cisco/config/platform/rmdb/" ascii
        $p_lina      = "lina" ascii fullword
        $p_lina2     = "lina_monitor" ascii

        // WebVPN endpoint string used by passive trigger
        $p_cscoe     = "/+CSCOE+/" ascii

        // Magic-bytes prefix table fragments (passive trigger marker family)
        $magic_tag1  = "MZ\x90" ascii   // embedded marker (not the PE header)
        $magic_tag2  = "FSX-" ascii nocase
        $magic_tag3  = "FSXT" ascii nocase

        // Linux signal handling strings (graceful shutdown rewrite)
        $sig_term    = "SIGTERM" ascii
        $sig_action  = "sigaction" ascii

        // RC4/XChaCha20-class indicators (for C2 wrapping)
        $crypto1     = "ChaCha20" ascii
        $crypto2     = "Poly1305" ascii

    condition:
        uint32(0) == 0x464C457F and       // ELF
        filesize < 5MB and
        $p_cscoe and
        2 of ($p_*) and
        ($p_mount or $p_rmdb) and
        ($sig_term or $sig_action) and
        (
            // any platform fingerprint anchor — keeps the rule selective
            any of ($magic_tag*) or any of ($crypto*)
        )
}
