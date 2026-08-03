rule OctLurk_Backdoor_XorKey_Exports
{
    // Detects the OctLurk backdoor/loader via its hard-coded XOR key string and the
    // service-loader export names used to stage the in-memory payload.
    meta:
        author = "Jarmi"
        description = "OctLurk in-memory backdoor loader (hard-coded XOR key + RegisterService/Refresh exports)"
        date = "2026-08-03"
        reference = "https://securelist.com/octlurk-silklurk-backdoors-central-asia/120840/"
        confidence = "high"
        family = "OctLurk"
    strings:
        $xorkey = "FDrertgr##@QEWASGkio865ehyf98foidsjzhug874392dfsREFDfdsAGH43wea98h" ascii
        $exp1 = "RegisterService" ascii
        $exp2 = "Refresh" ascii
        $exp3 = "curl_easy_escape" ascii
        $hdr = "zyxwvutsrqponmlkjihgfedcbaABCDEFGHIJKLMNOPQRSTUVWXYZ9876543210-_" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3MB and
        ($xorkey or $hdr) and
        ($exp1 or $exp2 or $exp3)
}

rule SilkLurk_Proxy_ConnectUA_Config
{
    // Detects SilkLurk loader/proxy via the fixed CONNECT User-Agent and config markers.
    meta:
        author = "Jarmi"
        description = "SilkLurk in-memory backdoor / proxy (CONNECT User-Agent + config markers)"
        date = "2026-08-03"
        reference = "https://thehackernews.com/2026/08/suspected-chinese-speaking-hackers.html"
        confidence = "medium"
        family = "SilkLurk"
    strings:
        $ua = "Chrome/86.0.4240.75 Safari/537.36" ascii
        $connect = "CONNECT %s:%d HTTP/1.1" ascii
        $proxyconn = "Proxy-Connection: Keep-Alive" ascii
        $sideload1 = "vulkan-1.dll" ascii wide
        $sideload2 = "RtkSmbusLoc.dll" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 3MB and
        (
            ($ua and ($connect or $proxyconn)) or
            $sideload1 or $sideload2
        )
}
