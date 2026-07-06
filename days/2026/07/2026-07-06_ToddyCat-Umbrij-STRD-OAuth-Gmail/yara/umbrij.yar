/*
   ToddyCat "Umbrij" OAuth-token stealer (Shadow Token via Remote Debug / STRD)
   Author: Jarmi
   Reference: https://securelist.com/toddycat-apt-umbrij-tool-and-oauth/120251/
   Note: Umbrij is a .NET/MSIL DLL obfuscated with ConfuserEx. String-based rules
   may be partially defeated by heavy obfuscation; the STRD heuristic below keys on
   behavioural artifact strings that must survive to be functional.
*/

rule Umbrij_ToddyCat_OAuth_Strings
{
    meta:
        author = "Jarmi"
        description = "ToddyCat Umbrij OAuth stealer - Google OAuth endpoint fragments, abused migration-app client IDs and profile-copy artifacts"
        date = "2026-07-06"
        reference = "https://securelist.com/toddycat-apt-umbrij-tool-and-oauth/120251/"
        confidence = "high"
        family = "Umbrij"
    strings:
        $mz = { 4D 5A }
        $u1 = "o/oauth2/v2/auth/identifier" ascii wide
        $u2 = "flowName=GeneralOAuthFlow" ascii wide
        $c1 = "279448736670" ascii wide
        $c2 = "1095133494869" ascii wide
        $p1 = "BackupFiles" ascii wide
        $p2 = "--remote-debugging-port" ascii wide
    condition:
        $mz at 0 and filesize < 6MB and
        (
            ($u1 or $u2) and
            ($c1 or $c2) and
            ($p1 or $p2)
        )
}

rule Umbrij_ToddyCat_Log_Strings
{
    meta:
        author = "Jarmi"
        description = "ToddyCat Umbrij operator-log artifact strings (token impersonation and Puppeteer-driven consent clicks)"
        date = "2026-07-06"
        reference = "https://securelist.com/toddycat-apt-umbrij-tool-and-oauth/120251/"
        confidence = "high"
        family = "Umbrij"
    strings:
        $l1 = "ChekPortAvailable" ascii wide
        $l2 = "[pup] account choice click" ascii wide
        $l3 = "[pup] Allow click" ascii wide
        $l4 = "RevertToSelf succeed" ascii wide
        $l5 = "Impersonate" ascii wide
        $l6 = "detected profile" ascii wide
    condition:
        filesize < 6MB and
        (
            $l1 or $l2 or $l3 or $l4 or ($l5 and $l6)
        )
}

rule Umbrij_STRD_Heuristic
{
    meta:
        author = "Jarmi"
        description = "Heuristic for Shadow Token via Remote Debug OAuth stealers - headless Chromium driven via DevTools to mint an OAuth code from a copied profile"
        date = "2026-07-06"
        reference = "https://securelist.com/toddycat-apt-umbrij-tool-and-oauth/120251/"
        confidence = "medium"
        family = "Umbrij"
    strings:
        $h1 = "--remote-debugging-port" ascii wide
        $h2 = "--user-data-dir" ascii wide
        $h3 = "--headless" ascii wide
        $o1 = "accounts.google.com" ascii wide
        $o2 = "PuppeteerSharp" ascii wide
        $o3 = "CreateProcessAsUserW" ascii wide
    condition:
        filesize < 8MB and
        (
            ($h1 and $h3) and
            ($h2 or $o1) and
            ($o2 or $o3)
        )
}
