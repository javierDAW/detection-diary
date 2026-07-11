/*
   AIS / GNSS spoofing tooling and spoofed-capture heuristics.
   Author: Jarmi  Date: 2026-07-11
   These rules flag maritime AIS-spoofing and GNSS-spoofing tooling and captured
   NMEA/AIS artifacts that carry identity-falsification tells. They are structure /
   string heuristics for defensive triage of an analyst workstation, a bridge/VTS
   host or a feed collector - NOT confirmed-malicious sample signatures. Raw AIS is
   VHF and 6-bit ASCII-armored on the wire; these rules operate on tooling and on
   decoded / captured text. Reference: arXiv 2602.16257 SeaSpoofFinder; IFC AOR 2026-07-07.
*/

rule AIS_Spoofing_Simulator_Toolkit
{
    meta:
        author = "Jarmi"
        description = "AIS transmit/simulator tooling that can inject or fabricate AIS tracks (gr-ais, ais-simulator, AIVDM encoders)"
        date = "2026-07-11"
        reference = "https://arxiv.org/abs/2602.16257"
        confidence = "medium"
        family = "ais-spoofing-tooling"
    strings:
        $t1 = "ais-simulator" ascii nocase
        $t2 = "gr-ais" ascii nocase
        $t3 = "aisdeco" ascii nocase
        $t4 = "AIVDM" ascii
        $enc1 = "encode_ais" ascii nocase
        $enc2 = "def ais_encode" ascii nocase
        $enc3 = "sixbit" ascii nocase
        $tx1 = "hackrf_transfer" ascii nocase
        $tx2 = "osmocom_siggen" ascii nocase
    condition:
        filesize < 5MB and
        ( ($t1 or $t2 or $t3) or
          ($t4 and ($enc1 or $enc2 or $enc3)) or
          ($t4 and ($tx1 or $tx2)) )
}

rule AIS_Capture_Identity_Spoof_Tell
{
    meta:
        author = "Jarmi"
        description = "Captured NMEA/AIS text carrying identity-falsification tells: AIVDM sentences with generic vessel labels or placeholder MMSIs"
        date = "2026-07-11"
        reference = "https://safety4sea.com/ifc-ais-deception-drives-surge-in-maritime-cyber-security-incidents/"
        confidence = "low"
        family = "ais-spoofed-capture"
    strings:
        $aivdm = "!AIVDM" ascii
        $g1 = "NATO SHIP" ascii nocase
        $g2 = "FRENCH WARSHIP" ascii nocase
        $g3 = "SAMPLE" ascii
        $mmsi0 = "000000000" ascii
        $mmsi9 = "999999999" ascii
    condition:
        filesize < 50MB and $aivdm and
        ( $g1 or $g2 or $g3 or $mmsi0 or $mmsi9 )
}

rule GNSS_GPS_Spoofing_SDR_Tooling
{
    meta:
        author = "Jarmi"
        description = "GNSS/GPS signal-spoofing tooling and flowgraphs (gps-sdr-sim, spoofer scripts) that fabricate a counterfeit constellation"
        date = "2026-07-11"
        reference = "https://arxiv.org/abs/2602.16257"
        confidence = "medium"
        family = "gnss-spoofing-tooling"
    strings:
        $s1 = "gps-sdr-sim" ascii nocase
        $s2 = "gpssim" ascii nocase
        $s3 = "brdc" ascii
        $eph1 = "ephemeris" ascii nocase
        $eph2 = "RINEX" ascii
        $sdr1 = "bladeRF" ascii nocase
        $sdr2 = "hackrf" ascii nocase
        $sdr3 = "USRP" ascii
    condition:
        filesize < 5MB and
        ( ($s1 or $s2) or
          ($s3 and ($eph1 or $eph2)) or
          (($eph1 or $eph2) and ($sdr1 or $sdr2 or $sdr3)) )
}
