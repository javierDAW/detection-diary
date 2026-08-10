rule CornFlake_Go_RAT_Storm2945
{
    // Detects the CornFlake Windows Go RAT used by Storm-2945 (Midnight Blizzard) in the
    // CaptiveCrunch campaign, via its service-masquerade strings, self-copy path, runtime
    // config file name and the localhost HTTP API endpoints exposed to companion payloads.
    meta:
        author = "Jarmi"
        description = "CornFlake Go RAT - Cloud Sync Service masquerade + svchost32 self-copy + localhost API"
        date = "2026-08-10"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/"
        confidence = "medium"
        family = "CornFlake"
    strings:
        $svc = "Cloud Sync Service" ascii wide
        $desc = "Synchronizes files with the cloud storage provider" ascii wide
        $path = "svchost32" ascii wide
        $cfg = "sync.dat" ascii
        $api1 = "/upload" ascii
        $api2 = "/reload" ascii
        $api3 = "/status" ascii
        $go = "Go build ID:" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 20MB and
        (
            ($svc or $desc) and
            ($path or $cfg) and
            ($api1 or $api2 or $api3) and
            $go
        )
}

rule ChocoShell_PowerShell_Stealer_Storm2945
{
    // Detects the ChocoShell in-memory PowerShell credential stealer used in CaptiveCrunch, via
    // its hard-coded C2 URI artifacts, ABE-bypass remote-debugging path, UAC-bypass registry
    // value and Token Broker cache targeting. Text-based PowerShell payload - no MZ check.
    meta:
        author = "Jarmi"
        description = "ChocoShell PowerShell stealer - C2 pixel/polyfill/event URIs + CDP cookie theft + UAC bypass"
        date = "2026-08-10"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/"
        confidence = "medium"
        family = "ChocoShell"
    strings:
        $u1 = "/t/pixel.gif?m=" ascii
        $u2 = "/cdn/chunks/polyfill-7e2b.min.js" ascii
        $u3 = "/t/event" ascii
        $cdp = "Network.getAllCookies" ascii
        $dbg = "--remote-debugging-port" ascii
        $uac = "HKCU\\Environment" ascii
        $tok = ".tbres" ascii
        $wifi = "netsh wlan show profile" ascii
    condition:
        filesize < 512KB and
        (
            ($u1 or $u2 or $u3) and
            ($cdp or $dbg or $tok or $wifi or $uac)
        )
}
