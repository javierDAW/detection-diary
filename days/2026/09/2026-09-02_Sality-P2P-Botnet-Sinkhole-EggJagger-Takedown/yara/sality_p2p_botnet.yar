/*
   Sality (CrowdStrike: SALTY SPIDER) - P2P file-infector botnet disrupted 2026-08-31
   Sources: CrowdStrike Counter Adversary Operations, 2026-09-01 (published YARA rules CrowdStrike_Salityv3_01 and
   CrowdStrike_Salityv4_01) and the 2011 Symantec whitepaper by Nicolas Falliere (legacy strings).
   Rules 1 and 2 anchor on the string IPFILTERDRIVER plus the first 16 bytes of the embedded RSA public key that CrowdStrike
   publishes in full (128 bytes for v3, 256 bytes for v4); use the vendor rule for the full key. Rule 3 covers 2011-era strings and
   is low confidence for 2026 builds.
   Author: Jarmi
*/

rule Sality_V3_Embedded_Key_Prefix
{
    meta:
        author = "Jarmi"
        description = "Sality v3 P2P network: IPFILTERDRIVER string with the leading bytes of the embedded RSA public key published by CrowdStrike"
        date = "2026-09-02"
        reference = "https://www.crowdstrike.com/en-us/blog/inside-sality-botnet-disruption-operation/"
        confidence = "high"
        family = "Sality"

    strings:
        $drv = "IPFILTERDRIVER" ascii wide
        $key = { 99 65 40 34 CD AE 9D B3 AF F5 82 AD 8C 2E 63 51 }

    condition:
        uint16(0) == 0x5A4D
        and filesize < 10MB
        and $drv
        and $key
}

rule Sality_V4_Embedded_Key_Prefix
{
    meta:
        author = "Jarmi"
        description = "Sality v4 P2P network: IPFILTERDRIVER string with the leading bytes of the embedded RSA public key published by CrowdStrike"
        date = "2026-09-02"
        reference = "https://www.crowdstrike.com/en-us/blog/inside-sality-botnet-disruption-operation/"
        confidence = "high"
        family = "Sality"

    strings:
        $drv = "IPFILTERDRIVER" ascii wide
        $key = { BB D2 96 8E ED 0B 93 8A 82 E4 E9 BC C3 C5 32 72 }

    condition:
        uint16(0) == 0x5A4D
        and filesize < 10MB
        and $drv
        and $key
}

rule Sality_Legacy_2011_Strings
{
    meta:
        author = "Jarmi"
        description = "Legacy Sality builds documented by Symantec in 2011: user agent KUKU v3.09 exp, RC4 key string kukutrusted!, marker e#o203kjl,! and the polymorphic engine banner"
        date = "2026-09-02"
        reference = "https://git.vbrandl.net/vbrandl/masterthesis/raw/branch/master/references/2011_sality-story-of-peer-to-peer-11-en.pdf"
        confidence = "low"
        family = "Sality"

    strings:
        $ua     = "KUKU v3.09 exp" ascii wide
        $rc4    = "kukutrusted!." ascii
        $marker = "e#o203kjl,!" ascii
        $poly   = "Simple Poly Engine v1.1a" ascii
        $svc    = "amsint32" ascii wide

    condition:
        uint16(0) == 0x5A4D
        and filesize < 10MB
        and (($ua and $rc4) or ($ua and $marker) or ($rc4 and $marker) or ($poly and $svc) or ($ua and $svc))
}
