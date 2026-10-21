/*
  Title: Hijacked ccTLD Google and YouTube hostnames in log exports and certificate dumps
  Author: Jarmi
  Date: 2026-10-21
  Reference: https://thehackernews.com/2026/10/attackers-hijack-gh-sl-and-as.html
  Scope: text artefacts (proxy and DNS log exports, Zeek ssl.log and x509.log, openssl x509 -text dumps, CT monitor exports, browser history exports).
  There is no malware sample in this case: the actor used a registry compromise, authoritative DNS changes and public CAs. The rules therefore only locate
  the seven hostnames named in public reporting; they were not run against a real artefact. The names are legitimate Google properties, so a hit is an
  exposure lead for the window 2026-09-22 to 2026-10-01, never a verdict.
*/

rule CCTLD_Hijack_Google_Hostnames_In_Text_Artefacts
{
    meta:
        author = "Jarmi"
        description = "Text artefact that mentions one of the seven Google or YouTube hostnames under .gh, .sl or .as named in reporting on the 2026 ccTLD registry hijacks"
        date = "2026-10-21"
        reference = "https://thehackernews.com/2026/10/attackers-hijack-gh-sl-and-as.html"
        confidence = "low"
        family = "ccTLD-registry-hijack-2026-09"
    strings:
        $h1 = "google.com.gh" ascii wide nocase
        $h2 = "youtube.com.gh" ascii wide nocase
        $h3 = "google.com.sl" ascii wide nocase
        $h4 = "youtube.sl" ascii wide nocase
        $h5 = "youtube.as" ascii wide nocase
        $h6 = "google.sl" ascii wide nocase
        $h7 = "google.as" ascii wide nocase
    condition:
        filesize < 100MB and ($h1 or $h2 or $h3 or $h4 or $h5 or $h6 or $h7)
}

rule CCTLD_Hijack_Certificate_Dump_Non_Google_Issuer
{
    meta:
        author = "Jarmi"
        description = "Text dump of a certificate (openssl x509 -text or similar) that lists a hijacked ccTLD Google or YouTube name in the SAN and names Lets Encrypt or ZeroSSL as the issuer"
        date = "2026-10-21"
        reference = "https://thehackernews.com/2026/10/attackers-hijack-gh-sl-and-as.html"
        confidence = "low"
        family = "ccTLD-registry-hijack-2026-09"
    strings:
        $san1 = "DNS:google.com.gh" ascii nocase
        $san2 = "DNS:youtube.com.gh" ascii nocase
        $san3 = "DNS:google.sl" ascii nocase
        $san4 = "DNS:google.com.sl" ascii nocase
        $san5 = "DNS:youtube.sl" ascii nocase
        $san6 = "DNS:google.as" ascii nocase
        $san7 = "DNS:youtube.as" ascii nocase
        $iss1 = "Let's Encrypt" ascii nocase
        $iss2 = "ZeroSSL" ascii nocase
    condition:
        filesize < 1MB and ($san1 or $san2 or $san3 or $san4 or $san5 or $san6 or $san7) and ($iss1 or $iss2)
}
