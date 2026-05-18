/*
   Silver Fox ABCDoor + RustSL loader YARA pack
   Author: Jarmi
   Date: 2026-05-18
   Reference: https://securelist.com/silver-fox-tax-notification-campaign/119575/
   Confidence: high (combinations of unique string anchors)
   Family: ABCDoor / RustSL / Silver Fox / SwimSnake / Void Arachne / UTG-Q-1000
*/

rule ABCDoor_AppClient_Python_Implant_2026
{
    meta:
        author = "Jarmi"
        description = "Silver Fox ABCDoor Python backdoor — Cython-compiled appclient.core module with Socket.IO C2"
        date = "2026-05-18"
        reference = "https://securelist.com/silver-fox-tax-notification-campaign/119575/"
        confidence = "high"
        family = "ABCDoor"
        cluster = "Silver Fox / SwimSnake / Void Arachne"

    strings:
        // Cython 3.x compiled .pyd anchor (older builds 3.0.7 / 3.0.12)
        $cy1 = "Cython 3.0." ascii
        // Canonical entry point and module name
        $m1  = "appclient.core" ascii
        $m2  = "AppClientABC" ascii
        $m3  = "python(" ascii
        // Manager classes that the disassembled .pyd exports
        $cls1 = "MainManager" ascii
        $cls2 = "AutoStartManager" ascii
        $cls3 = "RemoteControlManager" ascii
        $cls4 = "SystemInfoManager" ascii
        $cls5 = "ClipboardManager" ascii
        $cls6 = "ScreenRecorder" ascii
        // Persistence anchors
        $p1 = "schtasks /create /sc minute /mo 1 /tn \"AppClient\"" ascii
        $p2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
        $p3 = "Software\\CarEmu" ascii
        // C2 / network anchors
        $c1 = "device.log" ascii
        $c2 = "PythonDownloader" ascii
        $c3 = "MachineGuid" ascii
        // DirectX desktop duplication API anchor for screen broadcasting
        $d1 = "ddagrab" ascii
        $d2 = "test_ddagrab_support" ascii

    condition:
        filesize < 20MB
        and uint16(0) == 0x5A4D                       // MZ for compiled .pyd
        and $cy1
        and any of ($m*)
        and 3 of ($cls*)
        and 1 of ($p*)
        and 1 of ($c*)
        and 1 of ($d*)
}

rule RustSL_Loader_Phantom_Persistence_2026
{
    meta:
        author = "Jarmi"
        description = "Silver Fox RustSL loader — Rust-compiled binary with Phantom Persistence shutdown-signal hijack and Halo's Gate indirect syscalls"
        date = "2026-05-18"
        reference = "https://securelist.com/silver-fox-tax-notification-campaign/119575/"
        confidence = "high"
        family = "RustSL"
        cluster = "Silver Fox / SwimSnake / Void Arachne"

    strings:
        // Verbatim payload markers used by RustSL to delimit encrypted blob
        $m1 = "<RSL_START>" ascii
        $m2 = "<RSL_END>" ascii
        // XOR key embedded in the loader
        $k1 = "RSL_STEG_2025_KEY" ascii
        // Phantom Persistence debug-log banner — verbatim from the Securelist analysis
        $pp1 = "rsl_debug.log" ascii
        $pp2 = "God-Tier Telemetry Blinding" ascii
        $pp3 = "HalosGate" ascii
        $pp4 = "Indirect Syscalls" ascii
        // Phantom Persistence Win32 anchors
        $w1 = "RegisterApplicationRestart" ascii
        $w2 = "SetProcessShutdownParameters" ascii
        $w3 = "EWX_RESTARTAPPS" ascii
        // Geofence anchors (IP-based country detection)
        $g1 = "ip-api.com" ascii
        $g2 = "ipinfo.io" ascii
        $g3 = "ipwho.is" ascii
        $g4 = "geoplugin.net" ascii
        // Country allow-list anchors
        $cc1 = "RU" ascii fullword
        $cc2 = "IN" ascii fullword
        $cc3 = "ID" ascii fullword
        $cc4 = "ZA" ascii fullword
        $cc5 = "JP" ascii fullword

    condition:
        filesize < 30MB
        and uint16(0) == 0x5A4D
        and (any of ($m*) and $k1)
        and (2 of ($pp*) or (1 of ($pp*) and 1 of ($w*)))
        and 2 of ($g*)
        and 3 of ($cc*)
}
