/*
  YARA Rule: SRG / Luna Moth - Known Fast Flux Domain Strings
  Author: Jarmi
  Date: 2026-06-24
  Description: Detects presence of known Silent Ransom Group (SRG) fast flux domain strings
               in memory dumps, network captures (raw PCAP bytes), DNS resolver logs, or
               process memory artifacts. These domains have no legitimate use and their
               presence in any artifact warrants investigation.
  Reference: https://www.resecurity.com/blog/article/silent-ransom-group-srg-uncovering-dns-fast-flux-infrastructure
  Confidence: high (known IOC domains); medium (heuristic string match in memory)
  Note: HEURISTIC — no binary sample hash available. Domain strings are publicly attributed IOCs.
        This rule fires on string presence only; validate with DNS query logs and network context.
  Family: SilentRansomGroup
*/

rule SRG_LunaMoth_FastFlux_Domains
{
    meta:
        author = "Jarmi"
        description = "Detects known SRG / Luna Moth fast flux C2 and leak site domains in artifacts"
        date = "2026-06-24"
        reference = "https://www.resecurity.com/blog/article/silent-ransom-group-srg-uncovering-dns-fast-flux-infrastructure"
        confidence = "high"
        family = "SilentRansomGroup"

    strings:
        $domain_c2   = "ep6pheij" ascii wide nocase
        $domain_leak = "business-data-leaks" ascii wide nocase

    condition:
        filesize < 20MB
        and ($domain_c2 or $domain_leak)
}

rule SRG_LunaMoth_FastFlux_DNS_TTL_Indicator
{
    meta:
        author = "Jarmi"
        description = "Detects DNS response record in a network capture with SRG domain and very short TTL, indicative of fast flux behavior"
        date = "2026-06-24"
        reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-093a"
        confidence = "medium"
        family = "SilentRansomGroup"
        note = "Applies to raw PCAP or DNS log line artifacts; TTL <= 60s pattern captured as bytes 0x00 0x00 0x00 3c (60 decimal) or less in DNS wire format following domain label"

    strings:
        $domain_c2   = "ep6pheij" ascii wide nocase
        $domain_leak = "business-data-leaks" ascii wide nocase
        // DNS TTL field <= 60 seconds (0x0000003c) in big-endian wire format
        $ttl_60      = { 00 00 00 3C }
        $ttl_30      = { 00 00 00 1E }
        $ttl_10      = { 00 00 00 0A }

    condition:
        filesize < 5MB
        and ($domain_c2 or $domain_leak)
        and 1 of ($ttl_*)
}
