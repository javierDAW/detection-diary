/*
   ip6.arpa Reverse-DNS Phishing - email / HTML body detections.
   Matches a saved email (.eml) or HTML lure whose clickable content is an
   image or anchor pointing at an ip6.arpa reverse-DNS host, and a second rule
   for the known Campaign A/B reverse zones. Pair with the dns_query Sigma and
   the Suricata dns.query signatures for resolver/network coverage.
   Reference: Infoblox (2026-02-26), BleepingComputer (2026-03-08), CloudSEK (2026-03-25).
   Author: Jarmi
*/

rule ip6arpa_Phishing_Email_ImageLink
{
    meta:
        author = "Jarmi"
        description = "Email/HTML carrying an image or anchor link to an ip6.arpa reverse-DNS host"
        date = "2026-06-03"
        reference = "https://www.cloudsek.com/blog/ip6-arpa-wildcard-abuse-hunting-phishing-infrastructure-across-ipv6-prefixes"
        confidence = "medium"
        family = "ip6arpa-phishing"
    strings:
        $arpa   = ".ip6.arpa" ascii nocase
        $href   = "href=" ascii nocase
        $img    = "<img" ascii nocase
        $http   = "http" ascii nocase
        $re     = /[a-z0-9]{4,}(\.[0-9a-f]){6,}\.ip6\.arpa/ ascii nocase
    condition:
        filesize < 2MB and
        $arpa and $http and ($re or ($href and $img))
}

rule ip6arpa_Phishing_Known_Zones
{
    meta:
        author = "Jarmi"
        description = "Known Campaign A/B ip6.arpa reverse zones and related phishing host"
        date = "2026-06-03"
        reference = "https://www.bleepingcomputer.com/news/security/hackers-abuse-arpa-dns-and-ipv6-to-evade-phishing-defenses/"
        confidence = "high"
        family = "ip6arpa-phishing"
    strings:
        $zoneA = "d.d.e.0.6.3.0.0.0.7.4.0.1.0.0.2.ip6.arpa" ascii nocase
        $zoneB = "0.d.7.2.7.0.1.b.e.0.a.2.ip6.arpa" ascii nocase
        $hostB = "t-w.dev" ascii nocase
        $sld   = "hekeroyot.com" ascii nocase
    condition:
        filesize < 2MB and
        ($zoneA or $zoneB or $hostB or $sld)
}
