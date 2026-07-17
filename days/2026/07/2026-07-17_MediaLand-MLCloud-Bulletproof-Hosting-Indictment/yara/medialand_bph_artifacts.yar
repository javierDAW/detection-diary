/*
   Author: Jarmi
   Description: Text/config artifact matching for Media Land LLC / ML.Cloud LLC
                bulletproof-hosting infrastructure. This case has no
                Media-Land-authored malware sample -- Media Land sold hosting,
                it did not write malware -- so these rules intentionally scope
                to reverse-proxy configuration artifacts, fast-flux automation
                scripts, and "no-logs bulletproof" marketing/forum-post
                language recovered from leaked or seized documents (e.g. the
                April 2025 internal leak analyzed by Prodaft). Do not use
                these rules as a substitute for network-layer detection
                (see suricata/medialand_bph_netblocks.rules).
   Date: 2026-07-17
   Reference: https://news.risky.biz/risky-bulletin-hackers-leak-data-from-major-bulletproof-hosting-provider/
   Confidence: medium
   Family: n/a (infrastructure artifact, not malware)
*/

rule MediaLand_ReverseProxy_Config_Artifact
{
    meta:
        author = "Jarmi"
        description = "Detects Nginx/HAProxy reverse-proxy config files with upstream directives pointing at Media Land LLC (AS206728) netblocks"
        date = "2026-07-17"
        reference = "https://ipinfo.io/AS206728"
        confidence = "medium"
        family = "n/a"
    strings:
        $upstream1 = "45.141.85." ascii
        $upstream2 = "91.220.163." ascii
        $proxy_pass = "proxy_pass" ascii
        $upstream_block = "upstream" ascii
    condition:
        filesize < 5MB and
        ($upstream1 or $upstream2) and
        ($proxy_pass or $upstream_block)
}

rule MediaLand_FastFlux_Automation_Artifact
{
    meta:
        author = "Jarmi"
        description = "Detects zone-file or automation-script fragments consistent with fast-flux A-record rotation as described for Media Land-class bulletproof hosting"
        date = "2026-07-17"
        reference = "https://www.spamhaus.org/resource-hub/bulletproof-hosting/bulletproof-hosting-theres-a-new-kid-in-town/"
        confidence = "low"
        family = "n/a"
    strings:
        $ttl_short = "TTL 600" ascii nocase
        $arecord = /A[[:space:]]+IN[[:space:]]+A[[:space:]]+[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ ascii
        $dnsapi = "dnspod" ascii nocase
        $rotate = "rotate_a_record" ascii nocase
    condition:
        filesize < 5MB and
        $ttl_short and
        ($arecord or $dnsapi or $rotate)
}

rule MediaLand_BPH_Marketing_Text_Artifact
{
    meta:
        author = "Jarmi"
        description = "Detects underground-forum-style marketing text advertising no-log bulletproof hosting, useful for triaging leaked forum/chat archives such as the April 2025 Media Land leak"
        date = "2026-07-17"
        reference = "https://news.risky.biz/risky-bulletin-hackers-leak-data-from-major-bulletproof-hosting-provider/"
        confidence = "low"
        family = "n/a"
    strings:
        $bph1 = "bulletproof hosting" ascii nocase
        $bph2 = "no logs" ascii nocase
        $bph3 = "abuse ignored" ascii nocase
        $bph4 = "WebMoney accepted" ascii nocase
        $bph5 = "KVM VPS" ascii nocase
    condition:
        filesize < 2MB and
        ($bph1 or $bph3) and
        ($bph2 or $bph4 or $bph5)
}
