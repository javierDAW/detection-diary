/*
   Author: Jarmi
   Description: Detection rules for the Spirals ransomware family and its
   confirmed tunneling toolkit, based on the single publicly documented
   intrusion (Symantec Threat Hunter Team, 2026-07-16). Rule 1 and 2 are
   hash-anchored because no public sample is available for deep static
   analysis; rule 3 targets the ransom note artifact and the confirmed
   service-kill PowerShell one-liner, which are reusable strings even if
   the encryptor binary itself is rebuilt.
   Reference: https://www.security.com/threat-intelligence/ransomware-spirals-extortion
   Date: 2026-07-21
*/

rule Spirals_Ransomware_Payload
{
    meta:
        author = "Jarmi"
        description = "Matches the confirmed Spirals ransomware payload (bitsadmin.exe / vbr2116.exe) by SHA256 and by its Rust-toolchain and ransom-note-path artifacts"
        date = "2026-07-21"
        reference = "https://www.security.com/threat-intelligence/ransomware-spirals-extortion"
        confidence = "high"
        family = "Spirals"

    strings:
        $note_path = "RECOVERY_SECTION.log" ascii wide
        $rust_marker1 = "src/main.rs" ascii
        $rust_marker2 = "cargo" ascii nocase

    condition:
        filesize < 20MB
        and (
            hash.sha256(0, filesize) == "0f9574dc38e5c34a31153f0bcc603c6ec29cb3bf65c3d25380dbe86d42573141"
            or ($note_path and ($rust_marker1 or $rust_marker2))
        )
}

rule Spirals_Tunneling_Toolkit
{
    meta:
        author = "Jarmi"
        description = "Matches the confirmed tunneling/proxy/impersonation toolkit deployed alongside Spirals: revsocks, Chisel (renamed chrome.exe), a generic tunnel binary, Cloudflare Tunnel client, and a token impersonation tool"
        date = "2026-07-21"
        reference = "https://www.security.com/threat-intelligence/ransomware-spirals-extortion"
        confidence = "high"
        family = "Spirals"

    condition:
        filesize < 50MB
        and (
            hash.sha256(0, filesize) == "4cab935d0ec400059a3fcdc95b6623efdd51a61dff401fba8d5da244cc2de649"
            or hash.sha256(0, filesize) == "7f0d49b11d0a3697685622ce510c570199bf2dc76515b3f9a6b6735de8c9134b"
            or hash.sha256(0, filesize) == "84b9a9a1668145df04faa3d0e118e2f0acbebd3d9d260baf3a355b44c815c22d"
            or hash.sha256(0, filesize) == "862a3ca7e944ccf0ff3a6d556b34faade4b68343015c35a014a43725ac14a2a1"
            or hash.sha256(0, filesize) == "b5d598b00cc3a28cabc5812d9f762819334614bae452db4e7f23eefe7b081556"
        )
}

rule Spirals_Backup_Service_Kill_Script
{
    meta:
        author = "Jarmi"
        description = "Matches the PowerShell service-enumeration-and-stop one-liner used by Spirals to force-stop 23 backup, database, and virtualization services before encryption. Useful for script-block log or memory scanning, not just file scanning"
        date = "2026-07-21"
        reference = "https://www.security.com/threat-intelligence/ransomware-spirals-extortion"
        confidence = "medium"
        family = "Spirals"

    strings:
        $wmi_query = "Get-WmiObject Win32_Service" ascii wide
        $stop_call = "Stop-Service" ascii wide nocase
        $pattern1 = "*veeam*" ascii wide nocase
        $pattern2 = "*commvault*" ascii wide nocase
        $pattern3 = "*vmcompute*" ascii wide nocase

    condition:
        filesize < 5MB
        and $wmi_query
        and $stop_call
        and ($pattern1 or $pattern2 or $pattern3)
}
