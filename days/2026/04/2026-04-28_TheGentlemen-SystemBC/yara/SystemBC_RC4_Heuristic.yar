rule SystemBC_RC4_SOCKS5_Heuristic
{
    meta:
        author       = "Jarmi"
        description  = "Heuristic for SystemBC custom RC4-encrypted SOCKS5 proxy: small PE/DLL with embedded key-schedule artifacts, hard-coded port table, and IPv4 dotted strings consistent with C2 hardcoding."
        date         = "2026-04-28"
        reference    = "https://research.checkpoint.com/"
        confidence   = "medium (heuristic — tune per environment)"
        family       = "SystemBC"

    strings:
        // SOCKS5 protocol bytes appearing as immediates
        $socks_handshake = { 05 01 00 }
        $socks_v5_reply  = { 05 00 00 01 }

        // RC4 KSA / PRGA loop fingerprints
        $rc4_kbox_init   = { 8A 04 1? 88 04 1? 4? 81 F? 00 01 }
        $rc4_swap_macro  = { 8A 14 30 8A 04 31 88 04 30 88 14 31 }

        // Common SystemBC string heuristics
        $s_useragent  = "Mozilla/5.0" ascii
        $s_taskname   = "socks5" ascii nocase
        $s_id_marker  = "ID:" ascii
        $s_proxyport  = "4001" ascii
        $s_proxyport2 = "443" ascii

        // Imports (dynamic resolution typical, but shipping samples often keep these)
        $api_ws       = "WSAStartup" ascii
        $api_conn     = "connect" ascii
        $api_send     = "send" ascii
        $api_recv     = "recv" ascii
        $api_thread   = "CreateThread" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 400KB and
        ( all of ($socks*) or all of ($rc4*) ) and
        3 of ($s_*) and
        3 of ($api_*)
}
