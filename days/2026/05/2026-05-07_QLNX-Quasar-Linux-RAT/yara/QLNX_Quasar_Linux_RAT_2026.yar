/*
   Author:      Jarmi
   Date:        2026-05-07
   Family:      QLNX (Quasar Linux RAT)
   Reference:   https://www.trendmicro.com/en_us/research/26/e/quasar-linux-qlnx-a-silent-foothold-in-the-software-supply-chain.html
                https://www.securityweek.com/sophisticated-quasar-linux-rat-targets-software-developers/
                https://socprime.com/active-threats/qlnx-linux-rat-uses-rootkit-and-pam-backdoor/
*/

rule QLNX_Quasar_Linux_RAT_2026
{
    meta:
        author      = "Jarmi"
        description = "Heuristic for QLNX (Quasar Linux RAT, Trend Micro May 2026): ELF magic + QLNX_MANAGED marker, embedded credential paths, master password, X11 lock anchor and ip-api recon string."
        date        = "2026-05-07"
        reference   = "https://www.trendmicro.com/en_us/research/26/e/quasar-linux-qlnx-a-silent-foothold-in-the-software-supply-chain.html"
        family      = "QLNX"
        confidence  = "medium-high (multi-anchor heuristic, not a per-sample SHA pin)"

    strings:
        $elf_magic        = { 7F 45 4C 46 }

        // QLNX-unique markers
        $marker_managed   = "QLNX_MANAGED" ascii
        $x11_lock         = ".X752e2ca1-lock" ascii
        $ice_unix_path    = "/var/log/.ICE-unix" ascii
        $master_pw        = "O$$f$QtYJK" ascii
        $version_str      = "1.4.1" ascii

        // Geolocation enrichment in the initial beacon
        $ipapi            = "ip-api.com" ascii

        // System paths the implant rewrites
        $ld_preload       = "/etc/ld.so.preload" ascii
        $machine_id       = "/etc/machine-id" ascii

        // Embedded C source string literals (compiled on-host)
        $emb_pam_hook     = "pam_get_authtok" ascii
        $emb_ld_audit     = "la_objsearch" ascii
        $gcc_invoke       = "-shared -fPIC" ascii

        // Developer-credential targets
        $cred_npmrc       = ".npmrc" ascii
        $cred_pypirc      = ".pypirc" ascii
        $cred_aws         = ".aws/credentials" ascii
        $cred_kube        = ".kube/config" ascii
        $cred_docker      = ".docker/config.json" ascii
        $cred_git         = ".git-credentials" ascii
        $cred_vault       = ".vault-token" ascii

        // DJB2("quasar_linux") = 0x752e2ca1, sometimes appears as immediate
        $djb2_imm         = { A1 2C 2E 75 }

        // String "quasar_linux" (often referenced by the lock-builder)
        $self_name        = "quasar_linux" ascii

    condition:
        $elf_magic at 0
        and filesize < 30MB
        and (
            // High-confidence: any one unique marker
            $marker_managed or $x11_lock or $master_pw
            or
            // Two or more behavior anchors
            ( 2 of ($emb_pam_hook, $emb_ld_audit, $gcc_invoke, $ld_preload, $ice_unix_path, $ipapi, $self_name, $version_str, $djb2_imm)
              and 3 of ($cred_npmrc, $cred_pypirc, $cred_aws, $cred_kube, $cred_docker, $cred_git, $cred_vault, $machine_id) )
        )
}
