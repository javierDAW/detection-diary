/*
   BumbleBee -> AdaptixC2 -> Akira intrusion set - tooling and host artifact strings.
   Author: Jarmi
   Date: 2026-07-03
   Reference: https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/
              https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a
   Notes: The BumbleBee loader (msimg32.dll) and the AdaptixC2 beacon (renamed
          wab.exe) are best caught behaviorally (see sigma/, kql/) - their bytes
          rotate. These rules anchor on the Akira family markers (cited to CISA),
          the Veeam DPAPI credential-dump PowerShell, and the SoftPerfect Network
          Scanner recon tool. Confirm against a sample before enforcing.
*/

rule Akira_Windows_Locker_Markers
{
    meta:
        author = "Jarmi"
        description = "Akira Windows locker family markers: extension, ransom note, CLI flags"
        date = "2026-07-03"
        reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a"
        confidence = "medium"
        family = "Akira"
    strings:
        $ext = ".akira" ascii wide
        $note = "akira_readme.txt" ascii wide nocase
        $flag_n = "-n=" ascii wide
        $flag_p = "-p=" ascii wide
        $net = "netonly" ascii wide
    condition:
        filesize < 8MB and ( $ext or $note ) and ( $flag_n or $flag_p or $net )
}

rule Veeam_Credential_Dump_PowerShell
{
    meta:
        author = "Jarmi"
        description = "Veeam PostgreSQL credential-dump plus DPAPI-decrypt tooling observed in this intrusion set"
        date = "2026-07-03"
        reference = "https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/"
        confidence = "medium"
        family = "ToolingVeeamDump"
    strings:
        $q1 = "VeeamBackup" ascii wide nocase
        $q2 = "credentials" ascii wide nocase
        $q3 = "user_name" ascii wide nocase
        $psql = "psql" ascii wide nocase
        $b64 = "JABQAG8AcwB0AGcAcgB1AFMAcQBs" ascii
    condition:
        filesize < 2MB and ( ( $q1 and $q2 ) or ( $psql and $q3 ) or $b64 )
}

rule SoftPerfect_NetScan_Recon_Tool
{
    meta:
        author = "Jarmi"
        description = "SoftPerfect Network Scanner (renamed n.exe) used for internal recon - dual-use tool"
        date = "2026-07-03"
        reference = "https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/"
        confidence = "low"
        family = "ToolingNetScan"
    strings:
        $s1 = "SoftPerfect Network Scanner" ascii wide
        $s2 = "netscan" ascii wide nocase
        $company = "SoftPerfect Pty Ltd" ascii wide
    condition:
        filesize < 12MB and $s1 and ( $s2 or $company )
}
