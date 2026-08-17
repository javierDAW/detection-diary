/*
   PATCHCORD cluster - Acronis TRU, 2026-08-13
   Campaign against Afghan telecom providers and South Asian critical infrastructure,
   overlapping with the APT36 / Transparent Tribe cluster with moderate confidence.
   Three implant families share one persistence idea (browser shortcut hijacking) and
   three different command-and-control transports (custom HTTP, Google Sheets, GitHub Gists).
   Author: Jarmi
*/

rule PATCHCORD_Implant_Cpp
{
    meta:
        author = "Jarmi"
        description = "PATCHCORD C/C++ implant: BeaconBrowserHijack Run value, Beacon/1.0.0 user agent, /api.jsp tasking endpoint and the It's Work! termination string"
        date = "2026-08-17"
        reference = "https://www.acronis.com/en/tru/posts/patchcord-new-malware-cluster-targets-afghan-telecom-and-south-asian-critical-infrastructure/"
        confidence = "high"
        family = "PATCHCORD"

    strings:
        $marker  = "BeaconBrowserHijack" ascii wide
        $ua      = "Beacon/1.0.0" ascii wide
        $task    = "/api.jsp" ascii wide
        $client  = "clientId=" ascii wide
        $term    = "It's Work!" ascii wide
        $runkey  = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
        $lnk     = "\\*.lnk" ascii wide
        $bak     = ".backup" ascii wide
        $sys32   = "C:\\Windows\\System32" ascii wide
        $mz      = { 4D 5A }

    condition:
        $mz at 0
        and filesize < 4MB
        and ($marker or $ua or $term)
        and (($task and $client) or ($runkey and $lnk and $bak) or ($marker and $sys32))
}

rule SHEETCORD_Go_Implant
{
    meta:
        author = "Jarmi"
        description = "SHEETCORD Go implant: Google Sheets API v4 command and control with a hardcoded GCP service account, SystemHelper Startup persistence and temp_update.vbs shortcut rewriting"
        date = "2026-08-17"
        reference = "https://www.acronis.com/en/tru/posts/patchcord-new-malware-cluster-targets-afghan-telecom-and-south-asian-critical-infrastructure/"
        confidence = "high"
        family = "SHEETCORD"

    strings:
        $go1     = "main.installStartupEntry" ascii
        $go2     = "main.executeShellCommand" ascii
        $go3     = "main.getHostInfo" ascii
        $vbs1    = "SystemHelper.vbs" ascii wide
        $vbs2    = "temp_update.vbs" ascii wide
        $sheets  = "sheets.googleapis.com" ascii
        $svcacct = "service_account" ascii
        $goruntime = "go.buildid" ascii
        $browsers = "vivaldi" ascii wide
        $mz      = { 4D 5A }

    condition:
        $mz at 0
        and filesize < 30MB
        and $goruntime
        and (($go1 or $go2 or $go3) or ($vbs1 or $vbs2))
        and ($sheets or $svcacct or $browsers)
}

rule HACKERAI_C2_Agent
{
    meta:
        author = "Jarmi"
        description = "HACKERAI C2 Agent: AI-assisted implant using GitHub Gists for tasking and exfiltration, with junk-operation stalling and clear-text debug logging"
        date = "2026-08-17"
        reference = "https://www.acronis.com/en/tru/posts/patchcord-new-malware-cluster-targets-afghan-telecom-and-south-asian-critical-infrastructure/"
        confidence = "medium"
        family = "HACKERAI"

    strings:
        $junk    = "performJunkOperations" ascii
        $log     = "[LOG] Agent Started" ascii wide
        $sleep   = "randomSleep" ascii
        $gist1   = "api.github.com/gists" ascii
        $gist2   = "gist.githubusercontent.com" ascii
        $pat     = "ghp_" ascii
        $foo     = "foo" ascii fullword
        $bar     = "bar" ascii fullword
        $baz     = "baz" ascii fullword
        $mz      = { 4D 5A }

    condition:
        $mz at 0
        and filesize < 30MB
        and ($junk or $log)
        and (($gist1 or $gist2 or $pat) or ($sleep and $foo and $bar and $baz))
}
