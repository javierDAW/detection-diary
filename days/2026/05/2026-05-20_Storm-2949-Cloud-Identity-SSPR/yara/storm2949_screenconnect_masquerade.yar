/*
   Storm-2949 — ScreenConnect masquerade heuristics
   Author:   Jarmi
   Date:     2026-05-20
   Reference: Microsoft Defender Security Research blog 2026-05-18
   Notes:    Storm-2949 used a legitimate ScreenConnect (ConnectWise Control)
             installer pulled from operator-controlled infrastructure
             (185.241.208.243) and then masqueraded the installed service
             with Windows-component-like display names. The first rule is
             a heuristic anchor (vendor strings plus masquerade primitives)
             so it must be tuned in environments that legitimately deploy
             ConnectWise Control. The second rule matches operator IP
             literals and the IMDS token endpoint anchor.
*/

rule Storm2949_ScreenConnect_Masquerade_Heuristic_2026
{
    meta:
        author      = "Jarmi"
        description = "Heuristic ScreenConnect installer or client with Windows-component masquerade anchors observed in Storm-2949 (Microsoft Defender Security Research, 2026-05-18)"
        date        = "2026-05-20"
        reference   = "Microsoft Security Blog 2026-05-18 Storm-2949 disclosure"
        confidence  = "medium"
        family      = "ScreenConnect-masquerade"

    strings:
        $vendor_a = "ConnectWise Control" ascii wide
        $vendor_b = "ScreenConnect" ascii wide
        $vendor_c = "screenconnect.com" ascii wide nocase
        $svc_real = "ScreenConnect Client" ascii wide
        $masq_a   = "Windows Telemetry Service" ascii wide nocase
        $masq_b   = "Windows Update Helper" ascii wide nocase
        $masq_c   = "Windows Defender Cache" ascii wide nocase
        $masq_d   = "Microsoft Connectivity Service" ascii wide nocase
        $cmd_a    = "Set-MpPreference -DisableRealtimeMonitoring" ascii wide nocase
        $cmd_b    = "wevtutil cl Security" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D
        and filesize < 80MB
        and ( 2 of ($vendor_*) or ($svc_real and 1 of ($vendor_*)) )
        and ( 1 of ($masq_*) or 1 of ($cmd_*) )
}

rule Storm2949_OperatorInfra_IP_Anchor_2026
{
    meta:
        author      = "Jarmi"
        description = "Storm-2949 operator IPs and IMDS token endpoint as content anchors for installers, scripts, and configuration blobs (Microsoft Defender Security Research, 2026-05-18)"
        date        = "2026-05-20"
        reference   = "Microsoft Security Blog 2026-05-18 Storm-2949 disclosure"
        confidence  = "high"
        family      = "Storm2949-infra"

    strings:
        $ip_a = "185.241.208.243" ascii wide
        $ip_b = "176.123.4.44" ascii wide
        $ip_c = "91.208.197.87" ascii wide
        $imds_anchor = "169.254.169.254/metadata/identity" ascii wide

    condition:
        filesize < 20MB
        and ( any of ($ip_*) or $imds_anchor )
}
