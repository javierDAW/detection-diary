/*
   YARA rules — AMOS / Atomic macOS Stealer (OpenClaw-skill + ClickFix delivery)
   Author:      Jarmi
   Date:        2026-05-30
   Family:      AMOS (Atomic macOS Stealer) MaaS
   References:
     - https://www.trendmicro.com/en_us/research/26/b/openclaw-skills-used-to-distribute-atomic-macos-stealer.html
     - https://www.glueckkanja.com/en/posts/2026-04-10-incident-to-intelligence
     - https://www.microsoft.com/en-us/security/blog/2026/05/06/clickfix-campaign-uses-fake-macos-utilities-lures-deliver-infostealers/
     - https://www.intego.com/mac-security-blog/osx-amos-hunting-c2s-in-trojanized-electron-asar-payloads/

   Coverage:
     - amos_macho_keychain_exfil_stealer  Universal/thin Mach-O carrying Keychain + archive + exfil markers.
     - amos_openclaw_delivery_markers      OpenClaw-skill loader URLs and the report-upload endpoint / fields.
     - amos_wallet_extension_targeting     Hardcoded crypto-wallet browser-extension IDs.
     - amos_macos_vm_evasion               Emulation / VM evasion strings combined with stealer behaviour.
*/

rule amos_macho_keychain_exfil_stealer
{
    meta:
        author      = "Jarmi"
        date        = "2026-05-30"
        description = "AMOS macOS stealer Mach-O: login Keychain read + ditto staging + curl exfil + Keychain APIs"
        reference   = "https://www.glueckkanja.com/en/posts/2026-04-10-incident-to-intelligence"
        family      = "AMOS"
        confidence  = "high"

    strings:
        $macho_fat   = { CA FE BA BE }
        $macho_fat64 = { CA FE BA BF }
        $macho_64    = { CF FA ED FE }
        $keychain    = "Keychains/login.keychain-db" ascii
        $tmpzip      = "/tmp/out.zip" ascii
        $ditto       = "ditto -c -k --sequesterRsrc" ascii
        $api_cccrypt = "CCCrypt" ascii
        $api_keyfind = "SecKeychainFind" ascii
        $api_itemadd = "SecItemAdd" ascii

    condition:
        filesize < 8MB
        and ($macho_fat at 0 or $macho_fat64 at 0 or $macho_64 at 0)
        and $keychain
        and ($tmpzip or $ditto)
        and ($api_cccrypt or $api_keyfind or $api_itemadd)
}

rule amos_openclaw_delivery_markers
{
    meta:
        author      = "Jarmi"
        date        = "2026-05-30"
        description = "AMOS OpenClaw-skill delivery markers: loader URLs and report-upload endpoint/fields"
        reference   = "https://www.trendmicro.com/en_us/research/26/b/openclaw-skills-used-to-distribute-atomic-macos-stealer.html"
        family      = "AMOS"
        confidence  = "high"

    strings:
        $loader_ip   = "91.92.242.30" ascii
        $vercel      = "openclawcli.vercel.app" ascii
        $c2_domain   = "socifiapp.com" ascii
        $report_ep   = "/api/reports/upload" ascii
        $report_fld  = "report_file=@" ascii
        $build_tag   = "build_tag=" ascii

    condition:
        filesize < 8MB
        and ($loader_ip or $vercel or $c2_domain or $report_ep or $report_fld or $build_tag)
}

rule amos_wallet_extension_targeting
{
    meta:
        author      = "Jarmi"
        date        = "2026-05-30"
        description = "AMOS hardcoded crypto-wallet browser-extension IDs targeted for theft"
        reference   = "https://www.trendmicro.com/content/dam/trendmicro/global/en/research/26/b/amos-stealer-openclaw/ioc-malicious-openclaw-skills-used-to-distribute-atomic-macos-stealer.txt"
        family      = "AMOS"
        confidence  = "medium"

    strings:
        $metamask = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii
        $phantom  = "bfnaelmomeimhlpmgjnjophhpkkoljpa" ascii
        $tronlink = "ibnejdfjmmkpcnlpebklmnkoeoihofec" ascii
        $exodus   = "aholpfdialjgjfhomihkjbmgjidlcdno" ascii
        $coin98   = "aeachknmefphepccionboohckonoeemg" ascii

    condition:
        filesize < 8MB
        and ($metamask or $phantom or $tronlink or $exodus or $coin98)
}

rule amos_macos_vm_evasion
{
    meta:
        author      = "Jarmi"
        date        = "2026-05-30"
        description = "AMOS macOS VM/emulation evasion strings combined with stealer behaviour markers"
        reference   = "https://www.glueckkanja.com/en/posts/2026-04-10-incident-to-intelligence"
        family      = "AMOS"
        confidence  = "medium"

    strings:
        $chip_unknown = "Chip: Unknown" ascii
        $intel_c2     = "Intel Core 2" ascii
        $keychain     = "Keychains/login.keychain-db" ascii
        $tmpzip       = "/tmp/out.zip" ascii

    condition:
        filesize < 8MB
        and ($chip_unknown or $intel_c2)
        and ($keychain or $tmpzip)
}
