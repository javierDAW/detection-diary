// RedHook Android RAT -- ADB Wireless Debugging / Shizuku privilege-abuse variant
// (Group-IB, 2026-07-09; family first documented by Cyble, July 2025).
// These are repo-authored hunting rules anchored on the published file indicator
// and durable strings (bundled Shizuku-derived server, C2 REST endpoint paths),
// NOT a copy of any vendor signature set. Scan the APK and/or its extracted
// classes.dex / lib / resources (apktool / unzip) -- APK strings may be compressed
// inside the zip, so prefer scanning decoded artifacts for best coverage.
// Reference: https://www.group-ib.com/blog/redhook-android-rat-upgraded/

rule MAL_RedHook_APK_Known_Hash
{
    meta:
        author = "Jarmi"
        description = "RedHook Android RAT sample matching Group-IB's published file indicator"
        date = "2026-07-20"
        reference = "https://www.group-ib.com/blog/redhook-android-rat-upgraded/"
        confidence = "high"
        family = "RedHook"
        hash = "453333bffdd1850ea2e0647f7c805530b578919978a01b1e2be52d6eb2add946"
    strings:
        $libmx      = "libmx.so" ascii
        $auth       = "/auth/login" ascii
        $upload     = "/file/upload" ascii
        $adddevice  = "/member/info/addDevice" ascii
        $keylog     = "/member/info/addsKeyboardInput" ascii
        $sms        = "/member/info/addMessage" ascii
        $secver     = "/member/identity_verification/saveSecurityCode" ascii
        $c2domain   = "3n7wj.com" ascii nocase
    condition:
        filesize < 80MB
        and ($libmx
             or $c2domain
             or (2 of ($auth, $upload, $adddevice, $keylog, $sms, $secver)))
}

rule HUNT_RedHook_ADB_Shizuku_Privilege_Abuse_Generic
{
    meta:
        author = "Jarmi"
        description = "Generic heuristic for Android apps embedding an ADB client plus Shizuku-style privileged-server bootstrap; broad hunting rule, not family-specific"
        date = "2026-07-20"
        reference = "https://www.group-ib.com/blog/redhook-android-rat-upgraded/"
        confidence = "low"
        family = "Android-ADB-Privilege-Abuse-Generic"
    strings:
        $adb_pair       = "pairing code" ascii nocase
        $wireless_debug = "Wireless debugging" ascii nocase
        $dev_options    = "development_settings_enabled" ascii
        $wifi_adb       = "adb_wifi_enabled" ascii
        $write_secure   = "WRITE_SECURE_SETTINGS" ascii
        $loopback       = "127.0.0.1" ascii
        $shizuku        = "shizuku" ascii nocase
    condition:
        filesize < 80MB
        and $loopback
        and 2 of ($adb_pair, $wireless_debug, $dev_options, $wifi_adb, $write_secure, $shizuku)
}
