/*
   QTFY (QT, QTCYBER) - QScan and QTRouter hard-coded infrastructure
   Source: FBI / NSA / CNMF advisory JCSA-20260826-01 (2026-08-26) and DoJ press release 26-972.
   The DoJ states that the seized domains were hard-coded into both QScan and QTRouter software and used for communication and
   authentication. These rules therefore look for those domain strings inside Linux executables and shell scripts. No sample was
   reverse engineered for this entry: the rules encode the published statement and the published file names, and should be validated
   with a retro-hunt on your own corpus before they are used as detections.
   Author: Jarmi
*/

rule QTFY_Hardcoded_Infrastructure_ELF
{
    meta:
        author = "Jarmi"
        description = "Linux ELF containing QTFY QScan or QTRouter infrastructure domains (qt-proxy.org, qt-team.com, qtproxy.xyz) or the paired mq-task and mq-result hostnames"
        date = "2026-08-27"
        reference = "https://www.ic3.gov/CSA/2026/260826.pdf"
        confidence = "medium"
        family = "QTFY-QScan-QTRouter"

    strings:
        $d_org    = "qt-proxy.org" ascii wide
        $d_team   = "qt-team.com" ascii wide
        $d_xyz    = "qtproxy.xyz" ascii wide
        $d_secure = "securelink.qtproxy" ascii wide
        $q_task   = "mq-task" ascii wide
        $q_result = "mq-result" ascii wide

    condition:
        uint32(0) == 0x464c457f
        and filesize < 64MB
        and ($d_org or $d_team or $d_xyz or $d_secure or ($q_task and $q_result))
}

rule QTFY_Hardcoded_Infrastructure_Script
{
    meta:
        author = "Jarmi"
        description = "Shell script that references a QTFY infrastructure domain and downloads content, matching the staging scripts listed in the advisory file table (a, b, c, d, e, f and in.sh)"
        date = "2026-08-27"
        reference = "https://www.ic3.gov/CSA/2026/QTFY_IOC_Files.csv"
        confidence = "low"
        family = "QTFY-QScan-QTRouter"

    strings:
        $d_org  = "qt-proxy.org" ascii
        $d_team = "qt-team.com" ascii
        $d_xyz  = "qtproxy.xyz" ascii
        $f_curl = "curl " ascii
        $f_wget = "wget " ascii

    condition:
        uint16(0) == 0x2123
        and filesize < 200KB
        and ($d_org or $d_team or $d_xyz)
        and ($f_curl or $f_wget)
}
