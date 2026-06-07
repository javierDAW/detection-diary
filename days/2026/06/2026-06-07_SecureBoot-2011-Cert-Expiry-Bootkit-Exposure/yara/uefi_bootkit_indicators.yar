/*
   UEFI bootkit / revoked-boot-component indicators - ILLUSTRATIVE class detection.

   IMPORTANT: this 2026-06-07 entry is a Secure Boot certificate-expiry POSTURE case,
   not a live intrusion. There is no new sample shipped with the Microsoft "act now"
   advisory or the Eclypsium analysis. The rules below target the well-documented
   bootkit class that the frozen-DBX window (KEK CA 2011 expires 2026-06-24) keeps
   exploitable: BlackLotus (CVE-2023-24932), the CVE-2024-7344 Howyar reloader, and
   the Framework "Bombshell" signed-shell technique that NULLs gSecurity2. These are
   GENERIC and not unique to any current campaign - expect benign hits on legitimate
   EFI binaries, recovery tooling, and research samples. Correlate with the Sigma/KQL
   behavioural detections and the ESP/UEFI-variable IR steps in the README.

   References:
     https://media.defense.gov/2023/Jun/22/2003245723/-1/-1/0/CSI_BlackLotus_Mitigation_Guide.PDF
     https://www.eset.com/us/about/newsroom/press-releases/eset-research-discovers-uefi-secure-boot-bypass-vulnerability/
     https://eclypsium.com/blog/microsoft-secure-boot-certificates-expire-2026/
   Author: Jarmi
*/

rule UEFI_PE_TE_Boot_Application
{
    meta:
        author = "Jarmi"
        description = "Generic anchor: PE/COFF or TE image declaring an EFI_APPLICATION/BOOT subsystem - scopes the bootkit rules to actual EFI executables"
        date = "2026/06/07"
        reference = "https://uefi.org/specifications"
        confidence = "low"
        family = "UEFI-Generic"
    strings:
        $mz = { 4D 5A }                      // MZ / PE
        $te = { 56 5A }                      // 'VZ' Terse Executable (TE) header magic
        $sub_app = { 0A 00 }                 // IMAGE_SUBSYSTEM_EFI_APPLICATION (10)
        $sub_bsd = { 0B 00 }                 // IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER (11)
        $sub_rsd = { 0C 00 }                 // IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER (12)
    condition:
        filesize < 4MB and (($mz at 0) or ($te at 0)) and ($sub_app or $sub_bsd or $sub_rsd)
}

rule UEFI_SecureBoot_Bypass_Strings
{
    meta:
        author = "Jarmi"
        description = "Strings associated with disabling/subverting Secure Boot signature verification: gSecurity2 NULLing (Bombshell), LoadImage hooking, and integrity-check disable used by BlackLotus-class loaders"
        date = "2026/06/07"
        reference = "https://eclypsium.com/blog/microsoft-secure-boot-certificates-expire-2026/"
        confidence = "medium"
        family = "Bootkit-SecureBootBypass"
    strings:
        $g1 = "gSecurity2" ascii wide nocase
        $g2 = "EFI_SECURITY2_ARCH_PROTOCOL" ascii wide nocase
        $g3 = "FileAuthentication" ascii wide nocase
        $h1 = "LoadImage" ascii wide
        $h2 = "DISABLE_INTEGRITY_CHECKS" ascii wide nocase
        $h3 = "nointegritychecks" ascii wide nocase
    condition:
        filesize < 4MB and (($g1 and ($g2 or $g3)) or ($h1 and ($h2 or $h3)))
}

rule UEFI_Bootkit_BlackLotus_Reloader_Markers
{
    meta:
        author = "Jarmi"
        description = "Markers tied to BlackLotus-class staging and the CVE-2024-7344 Howyar reloader (unsigned payload loaded from a hardcoded path) - illustrative, not exploit-unique"
        date = "2026/06/07"
        reference = "https://www.eset.com/us/about/newsroom/press-releases/eset-research-discovers-uefi-secure-boot-bypass-vulnerability/"
        confidence = "medium"
        family = "Bootkit-BlackLotus"
    strings:
        $p1 = "\\EFI\\Microsoft\\Boot\\bootmgfw.efi" ascii wide nocase
        $p2 = "\\system32\\Boot\\winload" ascii wide nocase
        $r1 = "reloader.efi" ascii wide nocase
        $r2 = "cloak.dat" ascii wide nocase
        $r3 = "BlackLotus" ascii wide nocase
        $r4 = "Baton Drop" ascii wide nocase
    condition:
        filesize < 4MB and (($p1 and $p2) or $r1 or $r2 or $r3 or $r4)
}
