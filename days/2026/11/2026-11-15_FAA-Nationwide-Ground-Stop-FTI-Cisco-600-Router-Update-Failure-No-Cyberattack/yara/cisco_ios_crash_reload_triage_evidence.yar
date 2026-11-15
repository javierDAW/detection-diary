/*
   FAA nationwide ground stop (2026-11-13) - network-device crash / reload TRIAGE rules
   Author: Jarmi
   Date: 2026-11-15
   Reference: CBS News https://www.cbsnews.com/news/faa-issues-nationwide-ground-stop/ ;
              SecurityWeek https://www.securityweek.com/no-signs-of-hacking-in-faa-ground-stop-as-fbi-reportedly-probes-software-update/
   These are NOT malware signatures. The FAA case has no published malware, sample, hash, CVE or
   attacker TTP; officials reported no indication of a nefarious act and sources point to an update
   or new equipment overwhelming legacy routers (root cause not officially confirmed). These rules
   sort collected text evidence - crashinfo files, "show tech-support", "show version" and
   "show logging" captures, archived syslog - so an analyst can quickly find the devices that
   crashed, reloaded or ran out of resources. Strings are GENERIC Cisco IOS output, confidence LOW,
   NOT derived from FAA evidence (unpublished); no claim is made about what 600 series routers emit.
*/

rule Cisco_IOS_Crash_Evidence_Text
{
    meta:
        author = "Jarmi"
        description = "Cisco IOS text evidence (crashinfo / show version / show tech) recording an abnormal restart: bus error, crash, watchdog or traceback. Triage aid, not malware"
        date = "2026-11-15"
        reference = "https://www.cbsnews.com/news/faa-issues-nationwide-ground-stop/"
        confidence = "low"
        family = "network-device-triage"
    strings:
        $ios = "Cisco IOS Software" ascii nocase
        $ios_old = "Cisco Internetwork Operating System" ascii nocase
        $rom = "System returned to ROM by" ascii
        $tb = "Traceback=" ascii
        $bus = "bus error" ascii nocase
        $wd = "watchdog" ascii nocase
        $crash = "crashinfo" ascii nocase
    condition:
        filesize < 20MB and ($ios or $ios_old or $crash) and $rom and ($tb or $bus or $wd)
}

rule Cisco_IOS_Reload_Record_Text
{
    meta:
        author = "Jarmi"
        description = "Cisco IOS show version / show logging text recording a reload or restart (System returned to ROM, System restarted at, SYS-5-RELOAD / SYS-5-RESTART). Use to timeline reloads across a fleet; not malware"
        date = "2026-11-15"
        reference = "https://www.securityweek.com/no-signs-of-hacking-in-faa-ground-stop-as-fbi-reportedly-probes-software-update/"
        confidence = "low"
        family = "network-device-triage"
    strings:
        $rom = "System returned to ROM by" ascii
        $restarted = "System restarted at" ascii
        $uptime = "uptime is" ascii
        $reload = "%SYS-5-RELOAD" ascii
        $restart = "%SYS-5-RESTART" ascii
    condition:
        filesize < 20MB and ($rom or $restarted or $reload or $restart) and ($uptime or $reload or $restart)
}

rule Cisco_IOS_Resource_Exhaustion_Log_Text
{
    meta:
        author = "Jarmi"
        description = "Cisco IOS log or show tech text containing resource-exhaustion / crash-precursor messages (SYS-2-MALLOCFAIL, SYS-3-CPUHOG, SYS-2-WATCHDOG). Flags devices that could not absorb load; not malware"
        date = "2026-11-15"
        reference = "https://www.npr.org/2026/11/14/nx-s1-6040952/faa-ground-stop-airplane-travel"
        confidence = "low"
        family = "network-device-triage"
    strings:
        $malloc = "%SYS-2-MALLOCFAIL" ascii
        $cpuhog = "%SYS-3-CPUHOG" ascii
        $wdog = "%SYS-2-WATCHDOG" ascii
        $tb = "Traceback=" ascii
    condition:
        filesize < 50MB and ($malloc or $cpuhog or $wdog) and ($tb or $malloc or $wdog or $cpuhog)
}

rule Cisco_IOS_Config_Change_Then_Reload_Text
{
    meta:
        author = "Jarmi"
        description = "Single Cisco IOS log capture holding both a configuration change (SYS-5-CONFIG_I Configured from) and a reload / restart record - candidate change-induced fault, verify against change tickets; not malware"
        date = "2026-11-15"
        reference = "https://www.cnbc.com/2026/11/14/faa-ground-stop-flights-resume-delays.html"
        confidence = "low"
        family = "network-device-triage"
    strings:
        $cfg = "%SYS-5-CONFIG_I" ascii
        $cfgfrom = "Configured from" ascii
        $reload = "%SYS-5-RELOAD" ascii
        $restart = "%SYS-5-RESTART" ascii
    condition:
        filesize < 50MB and ($cfg or $cfgfrom) and ($reload or $restart)
}
