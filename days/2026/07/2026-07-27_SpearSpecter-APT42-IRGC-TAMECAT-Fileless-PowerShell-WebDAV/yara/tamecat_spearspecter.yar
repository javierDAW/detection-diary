/*
   TAMECAT / SpearSpecter (APT42 / IRGC-IO) detection rules.
   Targets the text-based PowerShell loader/config and the WebDAV LNK/batch
   initial-access artifacts. TAMECAT is fileless, so these rules are intended
   for memory captures, script-block log dumps, staged .bat/.txt loaders and
   recovered LNK command lines - not for a packed on-disk PE.
   Author: Jarmi
   Reference: https://govextra.gov.il/national-digital-agency/cyber/research/spearspecter/
*/

rule TAMECAT_SpearSpecter_Loader
{
    meta:
        author = "Jarmi"
        description = "TAMECAT modular PowerShell loader/config used by SpearSpecter (APT42): hardcoded AES key, Sec-Host IV header, workers.dev module map, wildcard iex and #journey control keyword"
        date = "2026-07-27"
        reference = "https://govextra.gov.il/national-digital-agency/cyber/research/spearspecter/"
        confidence = "high"
        family = "TAMECAT"
    strings:
        $aeskey = "g9944pf33sbuuuspi3z2er6rqh9ermxk" ascii wide
        $sechdr = "Sec-Host" ascii wide
        $journey = "#journey" ascii wide
        $iex1 = "gcm i*x" ascii wide
        $iex2 = "gcm i*ee*" ascii wide
        $w_base = "darijo-bosanac-dl.workers.dev" ascii wide
        $w_load = "line.completely.workers.dev" ascii wide
        $irm = "invoke-restmethod" ascii nocase wide
    condition:
        filesize < 300KB and
        (
            $aeskey or
            ($sechdr and $journey) or
            ($w_base and ($iex1 or $iex2)) or
            ($w_load and $irm)
        )
}

rule SpearSpecter_WebDAV_LNK_Batch
{
    meta:
        author = "Jarmi"
        description = "SpearSpecter (APT42) initial-access artifacts: rundll32 davclnt.dll DavSetCookie WebDAV reach-out and the curl download/rename-to-temp.bat loader stager"
        date = "2026-07-27"
        reference = "https://securityonline.info/iran-apt-spearspecter-uses-weeks-long-whatsapp-lures-and-fileless-tamecat-backdoor-to-hit-defense/"
        confidence = "high"
        family = "TAMECAT"
    strings:
        $dav = "DavSetCookie" ascii wide
        $davdll = "davclnt.dll" ascii nocase wide
        $curl = "--ssl-no-revoke" ascii wide
        $drop1 = "vgh.txt" ascii wide
        $drop2 = "temp.bat" ascii wide
        $somee = "datadrift.somee.com" ascii nocase wide
        $renov = "Renovation" ascii wide
        $logon = "UserInitMprLogonScript" ascii wide
    condition:
        filesize < 300KB and
        (
            ($dav and $davdll) or
            ($curl and ($drop1 or $drop2)) or
            $somee or
            ($renov and $logon)
        )
}
