// YARA rules for KongTuke/Woodgnat Backdoor.Mistic (MTLBackdoor) intrusion set
// Author: Jarmi
// Reference: https://www.security.com/threat-intelligence/new-mistic-backdoor-modelorat
// Behaviour-anchored, not a copy of any vendor ruleset. Bounded by filesize.

import "pe"

rule Mistic_Loader_VersionDLL_APIHooks
{
    meta:
        author = "Jarmi"
        description = "Mistic loader (version.dll) that hooks GetModuleFileNameW/LoadLibraryW to sideload the backdoor via signed MpExtMs.exe"
        date = "2026-07-07"
        reference = "https://www.security.com/threat-intelligence/new-mistic-backdoor-modelorat"
        confidence = "medium"
        family = "Mistic"
    strings:
        $host = "MpExtMs.exe" ascii wide nocase
        $dll  = "EndpointDlp.dll" ascii wide nocase
        $api1 = "GetModuleFileNameW" ascii
        $api2 = "LoadLibraryW" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2MB and
        ($host and $dll and ($api1 or $api2))
}

rule Backdoor_Mistic_EndpointDlp
{
    meta:
        author = "Jarmi"
        description = "Backdoor.Mistic (MTLBackdoor) DLL masquerading as EndpointDlp.dll; in-memory execution and BOF loading capabilities"
        date = "2026-07-07"
        reference = "https://thehackernews.com/2026/06/new-mistic-backdoor-linked-to-kongtuke.html"
        confidence = "low"
        family = "Mistic"
    strings:
        $n1 = "EndpointDlp.dll" ascii wide nocase
        $b1 = "beacon" ascii nocase
        $b2 = "BOF" ascii
        $c1 = "kill" ascii nocase
        $c2 = "sleep" ascii nocase
    condition:
        uint16(0) == 0x5A4D and filesize < 2MB and
        ($n1 and ($b1 or $b2) and ($c1 or $c2))
}

rule Woodgnat_FakeLockScreen_Stealer
{
    meta:
        author = "Jarmi"
        description = "Woodgnat .NET fake lock-screen credential stealer (f.dll) that renders a fake login to capture credentials"
        date = "2026-07-07"
        reference = "https://www.security.com/threat-intelligence/new-mistic-backdoor-modelorat"
        confidence = "low"
        family = "Woodgnat"
    strings:
        $net = "mscoree.dll" ascii nocase
        $s1  = "Password" wide nocase
        $s2  = "Sign in" wide nocase
        $s3  = "LockScreen" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and filesize < 1MB and
        ($net and ($s1 or $s2 or $s3))
}
