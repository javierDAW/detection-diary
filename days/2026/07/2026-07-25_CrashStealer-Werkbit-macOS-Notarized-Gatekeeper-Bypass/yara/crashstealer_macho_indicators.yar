/*
   YARA rules -- CrashStealer macOS Infostealer (notarized-dropper delivery)
   Author:      Jarmi
   Date:        2026-07-25
   Family:      CrashStealer (unattributed developer/operator)
   References:
     - https://securityaffairs.com/195278/malware/crashstealer-new-macos-infostealer-uses-signed-apps-to-evade-gatekeeper.html
     - https://thehackernews.com/2026/07/crashstealer-macos-malware-uses.html
     - https://www.jamf.com/blog/crashstealer-macos-infostealer-analysis/

   Coverage:
     - crashstealer_macho_crypto_staging_indicators   Mach-O carrying the salt
       string, .zx_ staging prefix, and CommonCrypto GCM API sequence.
     - crashstealer_launchagent_plist_impersonation    plist text indicators
       for the impersonating LaunchAgent label and bundle identifier.
     - crashstealer_anti_debug_sysctl_kern_proc        sysctl-based debugger
       check strings used by the layered anti-analysis logic.
*/

rule crashstealer_macho_crypto_staging_indicators
{
    meta:
        author      = "Jarmi"
        date        = "2026-07-25"
        description = "CrashStealer macOS infostealer Mach-O: PBKDF2 salt, .zx_ staging archive prefix, CommonCrypto GCM API sequence"
        reference   = "https://securityaffairs.com/195278/malware/crashstealer-new-macos-infostealer-uses-signed-apps-to-evade-gatekeeper.html"
        family      = "CrashStealer"
        confidence  = "high"

    strings:
        $macho_fat   = { CA FE BA BE }
        $macho_fat64 = { CA FE BA BF }
        $macho_64    = { CF FA ED FE }
        $salt        = "panel_salt_v1" ascii
        $salt_dev    = "using fallback salt" ascii
        $zx_prefix   = ".zx_" ascii
        $api_gcmset  = "CCCryptorGCMSetIV" ascii
        $api_gcmenc  = "CCCryptorGCMEncrypt" ascii
        $api_gcmfin  = "CCCryptorGCMFinal" ascii
        $api_pbkdf   = "CCKeyDerivationPBKDF" ascii
        $bundle_id   = "com.apple.crashreporter" ascii
        $dscl_auth   = "-authonly" ascii

    condition:
        filesize < 16MB
        and ($macho_fat at 0 or $macho_fat64 at 0 or $macho_64 at 0)
        and ($salt or $salt_dev or $zx_prefix)
        and ($api_gcmset or $api_gcmenc or $api_gcmfin or $api_pbkdf)
        and ($bundle_id or $dscl_auth)
}

rule crashstealer_launchagent_plist_impersonation
{
    meta:
        author      = "Jarmi"
        date        = "2026-07-25"
        description = "CrashStealer LaunchAgent plist impersonating Apple's crash-reporting naming"
        reference   = "https://www.jamf.com/blog/crashstealer-macos-infostealer-analysis/"
        family      = "CrashStealer"
        confidence  = "high"

    strings:
        $label       = "com.apple.crashreporter.helper" ascii
        $keepalive   = "KeepAlive" ascii
        $successful  = "SuccessfulExit" ascii
        $plist_open  = "<?xml version=" ascii
        $plist_type  = "<!DOCTYPE plist" ascii

    condition:
        ($plist_open or $plist_type)
        and $label
        and $keepalive
        and $successful
}

rule crashstealer_anti_debug_sysctl_kern_proc
{
    meta:
        author      = "Jarmi"
        date        = "2026-07-25"
        description = "CrashStealer sysctl KERN_PROC / P_TRACED debugger-attached check used before malicious behaviour runs"
        reference   = "https://securityaffairs.com/195278/malware/crashstealer-new-macos-infostealer-uses-signed-apps-to-evade-gatekeeper.html"
        family      = "CrashStealer"
        confidence  = "medium"

    strings:
        $sysctl_api  = "sysctl" ascii
        $kern_proc   = "kern.proc" ascii
        $p_traced    = "P_TRACED" ascii
        $exit_code   = { 6A 2D }

    condition:
        filesize < 16MB
        and $sysctl_api
        and ($kern_proc or $p_traced)
        and $exit_code
}
