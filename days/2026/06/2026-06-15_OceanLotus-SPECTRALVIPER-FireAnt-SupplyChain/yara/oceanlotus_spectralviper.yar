// OceanLotus (APT32) SPECTRALVIPER backdoor + FireAnt downloader (ESET, 11 June 2026).
// Repo-authored rules anchored on durable strings reported by ESET:
//   - RTTI class/method names recovered from an OPSEC-lapse sample (XGU framework).
//   - The HTTP Cookie beacon prefixes and hardcoded beacon URL path.
//   - The downloader next-stage API path.
// Confidence is high on the RTTI rule (group-internal symbol names), medium on the
// beacon/downloader rules (formats that could be imitated). TUNE before production.

rule OceanLotus_SPECTRALVIPER_RTTI
{
    meta:
        author = "Jarmi"
        description = "SPECTRALVIPER internal XGU framework RTTI class/method names (OceanLotus/APT32)"
        date = "2026-06-15"
        reference = "https://www.welivesecurity.com/en/eset-research/oceanlotus-external-espionage-domestic-targeting/"
        confidence = "high"
        family = "SPECTRALVIPER"
    strings:
        $x1 = "XGU::Pivot::StartLink" ascii
        $x2 = "XGU::Pivot::Internal::WaitNew_RemotePipe" ascii
        $x3 = "ProcessReflector" ascii
        $x4 = "ProcessManager" ascii
    condition:
        uint16(0) == 0x5A4D
        and filesize < 30MB
        and ($x1 or $x2 or ($x3 and $x4))
}

rule OceanLotus_SPECTRALVIPER_Beacon
{
    meta:
        author = "Jarmi"
        description = "SPECTRALVIPER HTTPS beacon markers: Cookie host-profiling prefixes and hardcoded beacon URL path"
        date = "2026-06-15"
        reference = "https://www.welivesecurity.com/en/eset-research/oceanlotus-external-espionage-domestic-targeting/"
        confidence = "medium"
        family = "SPECTRALVIPER"
    strings:
        $c1 = "zd_cs_pm=" ascii wide
        $c2 = "euconsent-v2=" ascii wide
        $u1 = "/apparatus/wind/twig/statement.html" ascii wide
        $u2 = "financemachinelearning.com" ascii wide
    condition:
        uint16(0) == 0x5A4D
        and filesize < 30MB
        and ($c1 or $c2 or $u1 or $u2)
}

rule OceanLotus_FireAnt_Downloader
{
    meta:
        author = "Jarmi"
        description = "OceanLotus SPECTRALVIPER downloader: FireAnt MetaKit next-stage API path and update markers"
        date = "2026-06-15"
        reference = "https://www.welivesecurity.com/en/eset-research/oceanlotus-external-espionage-domestic-targeting/"
        confidence = "medium"
        family = "SPECTRALVIPER-downloader"
    strings:
        $a1 = "V1/Update/GetUpdate" ascii wide
        $a2 = "metakit.fireant.vn" ascii wide
        $a3 = "/Software/setup.exe" ascii wide
    condition:
        uint16(0) == 0x5A4D
        and filesize < 10MB
        and ($a1 or $a2 or $a3)
}
