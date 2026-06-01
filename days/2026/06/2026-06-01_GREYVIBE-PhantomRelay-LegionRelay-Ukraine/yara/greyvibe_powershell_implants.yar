/*
   GREYVIBE PowerShell implant family - text/script detections.
   Targets the PhantomRelay fingerprinting stage, the LegionRelay REST client,
   and the PhantomRelay watchdog persistence script described by WithSecure
   (2026-05-28). These match PowerShell source text; pair with the canonical
   WithSecure YARA at github.com/WithSecureLabs/iocs/tree/master/GREYVIBE.
   Author: Jarmi
*/

rule GREYVIBE_PhantomRelay_Fingerprint
{
    meta:
        author = "Jarmi"
        description = "PhantomRelay PowerShell fingerprinting stage (history suppression + WMI UUID + hardcoded UA)"
        date = "2026-06-01"
        reference = "https://labs.withsecure.com/publications/greyvibe"
        confidence = "medium"
        family = "PhantomRelay"
    strings:
        $hist1 = "Set-PSReadlineOption -HistorySaveStyle SaveNothing" ascii wide nocase
        $hist2 = "Remove-Module PSReadline" ascii wide nocase
        $uuid  = "Win32_ComputerSystemProduct" ascii wide nocase
        $ua    = "Chrome/95.4.4476.124" ascii wide
        $cs    = "Win32_ComputerSystem" ascii wide nocase
    condition:
        filesize < 200KB and
        ($ua or (($hist1 or $hist2) and ($uuid or $cs)))
}

rule GREYVIBE_LegionRelay_Client
{
    meta:
        author = "Jarmi"
        description = "LegionRelay PowerShell REST RAT client (api endpoints + config + IEX background jobs)"
        date = "2026-06-01"
        reference = "https://labs.withsecure.com/publications/greyvibe"
        confidence = "medium"
        family = "LegionRelay"
    strings:
        $a1 = "/api/status" ascii wide nocase
        $a2 = "/api/register" ascii wide nocase
        $a3 = "/api/commands" ascii wide nocase
        $a4 = "/api/result" ascii wide nocase
        $a5 = "/api/upload" ascii wide nocase
        $cfg = "client_config.json" ascii wide nocase
        $iex = "Invoke-Expression" ascii wide nocase
    condition:
        filesize < 200KB and
        $cfg and $iex and ($a1 or $a2 or $a3 or $a4 or $a5)
}

rule GREYVIBE_PhantomRelay_Watchdog
{
    meta:
        author = "Jarmi"
        description = "PhantomRelay watchdog persistence script (RazerUpdater UA, razer_update.log, minute-interval scheduled task)"
        date = "2026-06-01"
        reference = "https://labs.withsecure.com/publications/greyvibe"
        confidence = "medium"
        family = "PhantomRelay"
    strings:
        $ua  = "RazerUpdater/3.0" ascii wide
        $log = "razer_update.log" ascii wide nocase
        $sc  = "/sc minute" ascii wide nocase
        $st  = "schtasks" ascii wide nocase
    condition:
        filesize < 200KB and
        ($ua or $log or ($st and $sc))
}
