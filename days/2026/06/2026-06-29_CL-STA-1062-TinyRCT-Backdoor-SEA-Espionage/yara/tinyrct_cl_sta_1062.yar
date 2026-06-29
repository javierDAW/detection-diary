/*
   CL-STA-1062 / TinyRCT detection rules
   Author: Jarmi
   Reference: https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/
   Note: Behavioral/string anchors for the TinyRCT .NET backdoor and its AppDomainManager
         loader. Hash pivots live in iocs.csv. Bounds kept tight to limit scan cost.
*/

import "pe"

rule TinyRCT_Backdoor_DotNet
{
    meta:
        author = "Jarmi"
        description = "TinyRCT .NET backdoor used by CL-STA-1062 (hardcoded AES key + masquerade name)"
        date = "2026-06-29"
        reference = "https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/"
        confidence = "high"
        family = "TinyRCT"
    strings:
        $aes_key = "ThisIsASecretKey87654321" ascii wide
        $mask    = "PerfWatson2.exe" ascii wide
        $choice  = "choice" ascii wide nocase
        $task    = "GoogleUpdaterTaskSystem" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 3MB and
        ($aes_key or ($mask and ($choice or $task)))
}

rule TinyRCT_AppDomainManager_Loader
{
    meta:
        author = "Jarmi"
        description = "Rogue AppDomainManager loader DLL paired with a hijacked .NET launcher config"
        date = "2026-06-29"
        reference = "https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/"
        confidence = "medium"
        family = "TinyRCT"
    strings:
        $adm     = "AppDomainManager" ascii wide
        $dllname = "MyAppDomainManager" ascii wide
        $perf    = "PerfWatson2" ascii wide
        $dl      = "139.180.134.221" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 2MB and
        ($dllname or ($adm and ($perf or $dl)))
}

rule TinyRCT_AppConfig_Hijack
{
    meta:
        author = "Jarmi"
        description = "Malicious .NET application config registering an attacker AppDomainManager assembly"
        date = "2026-06-29"
        reference = "https://attack.mitre.org/techniques/T1574/014/"
        confidence = "medium"
        family = "TinyRCT"
    strings:
        $cfg1 = "appDomainManagerAssembly" ascii wide nocase
        $cfg2 = "appDomainManagerType" ascii wide nocase
        $cfg3 = "MyAppDomainManager" ascii wide
        $hdr  = "<configuration" ascii wide nocase
    condition:
        filesize < 64KB and $hdr and (($cfg1 and $cfg2) or $cfg3)
}
