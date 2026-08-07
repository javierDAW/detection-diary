/*
   YARA rules -- macOS ClickFix TDS fingerprinting gate and lure page
   Author:      Jarmi
   Date:        2026-08-07
   Family:      Unattributed macOS ClickFix TDS operator (delivers AMOS / MacSync)
   References:
     - https://www.microsoft.com/en-us/security/blog/2026/08/05/macos-clickfix-campaign-learned-hide/
     - https://thehackernews.com/2026/08/over-250-clickfix-domains-use-browser.html

   Coverage:
     - clickfix_macos_tds_fingerprint_gate   The ~2.5 KB JS profiler served by the
       front-end domains: mode:"php" submission tag, canPlayType prototype tripwire,
       devtools toString counter, WebGL/touch/timezone/iframe environment probes.
     - clickfix_macos_lure_page              The gated "Download for macOS" lure HTML:
       forged Verified Publisher badge, clipboard-write of a curl one-liner, paste-to-
       Terminal instruction. Scoped to small HTML/JS documents.
*/

rule clickfix_macos_tds_fingerprint_gate
{
    meta:
        author      = "Jarmi"
        date        = "2026-08-07"
        description = "macOS ClickFix TDS fingerprinting gate JS: mode php tag, canPlayType tripwire, devtools toString counter, WebGL/touch probes"
        reference   = "https://www.microsoft.com/en-us/security/blog/2026/08/05/macos-clickfix-campaign-learned-hide/"
        confidence  = "medium"
        family      = "macos-clickfix-tds-gate"
    strings:
        $mode      = "mode:\"php\"" ascii wide nocase
        $mode2     = "mode:'php'" ascii wide nocase
        $canplay   = "canPlayType(\"video/mp4\")" ascii wide nocase
        $canplay2  = "canPlayType('video/mp4')" ascii wide nocase
        $proto     = "Array.prototype.includes" ascii wide
        $webgl     = "WEBGL_debug_renderer_info" ascii wide
        $webgl2    = "UNMASKED_RENDERER_WEBGL" ascii wide
        $plat      = "MacIntel" ascii wide
        $touch     = "ontouchstart" ascii wide
        $tzo       = "getTimezoneOffset" ascii wide
    condition:
        filesize < 64KB and
        ($mode or $mode2) and
        ($canplay or $canplay2 or $proto) and
        ($webgl or $webgl2 or $plat or $touch or $tzo)
}

rule clickfix_macos_lure_page
{
    meta:
        author      = "Jarmi"
        date        = "2026-08-07"
        description = "macOS ClickFix lure HTML: forged Verified Publisher badge, clipboard-write of a curl one-liner, paste-to-Terminal instruction"
        reference   = "https://thehackernews.com/2026/08/over-250-clickfix-domains-use-browser.html"
        confidence  = "medium"
        family      = "macos-clickfix-lure"
    strings:
        $verified  = "Verified Publisher" ascii wide nocase
        $download  = "Download for macOS" ascii wide nocase
        $clip      = "navigator.clipboard.writeText" ascii wide
        $exec      = "execCommand('copy')" ascii wide nocase
        $term      = "Terminal" ascii wide
        $curl      = "curl -fsSL" ascii wide nocase
        $curlpath  = "/curl/" ascii wide
    condition:
        filesize < 128KB and
        ($clip or $exec) and
        ($curl or $curlpath) and
        ($verified or $download or $term)
}
