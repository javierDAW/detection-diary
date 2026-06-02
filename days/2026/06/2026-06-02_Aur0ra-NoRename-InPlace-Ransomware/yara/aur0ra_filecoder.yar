/*
   Aur0ra ransomware - artifact and behaviour-string detections, plus the
   Remus Stealer string rule that shipped in the same CYFIRMA Weekly Intelligence
   Report (2026-05-22). Aur0ra encrypts in place with no rename and no extension,
   so the most portable signatures are the ransom note artifact and the embedded
   recovery-destruction command strings rather than ciphertext structure.
   No public Aur0ra binary string set exists yet; rules 1-2 target the note and
   the documented command strings, rule 3 is the secondary Remus Stealer.
   References:
     https://www.cyfirma.com/news/weekly-intelligence-report-22-may-2026/
     https://www.pcrisk.com/removal-guides/35259-aur0ra-ransomware
   Author: Jarmi
*/

rule Aur0ra_RansomNote
{
    meta:
        author = "Jarmi"
        description = "Aur0ra ransom note file (!!!README!!!DO_NOT_DELETE.txt) by filename marker and body text"
        date = "2026-06-02"
        reference = "https://www.pcrisk.com/removal-guides/35259-aur0ra-ransomware"
        confidence = "high"
        family = "Aur0ra"
    strings:
        $name = "!!!README!!!DO_NOT_DELETE.txt" ascii wide nocase
        $b1   = "We have downloaded confidential information files" ascii wide nocase
        $b2   = "Contact us via tor browser" ascii wide nocase
        $b3   = "Your access key:" ascii wide nocase
    condition:
        filesize < 20KB and ($name or $b1 or ($b2 and $b3))
}

rule Aur0ra_Filecoder_ShadowDelete_Strings
{
    meta:
        author = "Jarmi"
        description = "Heuristic: Aur0ra-style filecoder embedding VSS-deletion command strings alongside the note name"
        date = "2026-06-02"
        reference = "https://www.cyfirma.com/news/weekly-intelligence-report-22-may-2026/"
        confidence = "medium"
        family = "Aur0ra"
    strings:
        $note = "!!!README!!!DO_NOT_DELETE.txt" ascii wide nocase
        $v    = "vssadmin Delete Shadows /all /quiet" ascii wide nocase
        $w    = "wmic shadowcopy delete /nointeractive" ascii wide nocase
    condition:
        filesize < 5MB and $note and ($v or $w)
}

rule RemusStealer_String_Based_Detection
{
    meta:
        author = "Jarmi"
        description = "SECONDARY (not Aur0ra): Remus Stealer string detection, re-implemented from CYFIRMA's published rule"
        date = "2026-06-02"
        reference = "https://www.cyfirma.com/news/weekly-intelligence-report-22-may-2026/"
        confidence = "medium"
        family = "RemusStealer"
    strings:
        $hash = "48385492b6518cb2f3adcfd4a49c065ba960bdc617817068bd5faeb493d3f2db" ascii wide nocase
        $s1  = "cheapoca.biz" ascii wide nocase
        $s2  = "cheapoca.biz:5003" ascii wide nocase
        $s3  = "cheapoca.biz:500" ascii wide nocase
        $s4  = "wmiprvse.exe" ascii wide nocase
        $s5  = "wmiadap.exe" ascii wide nocase
        $s6  = "ROOT\\CIMV2" ascii wide nocase
        $s7  = "Win32_OperatingSystem" ascii wide nocase
        $s8  = "Win32_VideoController" ascii wide nocase
        $s9  = "{4590F811-1D3A-11D0-891F-00AA004B2E24}" ascii wide nocase
        $s10 = "\\Device\\KsecDD" ascii wide nocase
        $s11 = "amsi.dll" ascii wide nocase
        $s12 = "sysmain.sdb" ascii wide nocase
        $s13 = "bcryptprimitives.dll" ascii wide nocase
        $s14 = "rpcrt4.dll" ascii wide nocase
        $s15 = "SspiCli.dll" ascii wide nocase
        $s16 = "Outlook Files" ascii wide nocase
    condition:
        filesize < 10MB and ($hash or 10 of ($s*))
}
