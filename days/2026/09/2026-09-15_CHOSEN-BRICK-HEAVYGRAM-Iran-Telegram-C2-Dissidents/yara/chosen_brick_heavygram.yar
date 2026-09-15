/*
  CHOSEN BRICK (NCSC, AIVD) / HEAVYGRAM (FBI) - Iranian Telegram-C2 implants
  Author: Jarmi
  Date: 2026-09-15
  Reference: https://www.ic3.gov/CSA/2026/260915.pdf ; https://www.ic3.gov/CSA/2026/260915-2.pdf

  Scope and honesty note
  - The FBI analysis refers to "detection signatures" but none are included in the published text; these rules are built only
    from the strings and file names that the FBI and NCSC list (mutexes, staging folder and file names, Telegram Bot API calls).
  - The stage-2 implants are Python programs packed with PyInstaller, so strings that live in compressed bytecode are NOT
    expected in the file on disk. Rule 1 is meant for process memory or an unpacked bundle; rule 2 targets the stage-1 droppers
    by the file names they create; rule 3 targets dropped files and scripts that name the staging folders.
  - Confidence is medium or low throughout. Hash matching (iocs.csv) is the reliable detection for the 12 published samples.
*/

rule ChosenBrick_Heavygram_Mutex_And_Telegram_Api_Memory
{
    meta:
        author = "Jarmi"
        description = "Memory image or unpacked bundle holding a published CHOSEN BRICK mutex together with Telegram Bot API method names"
        date = "2026-09-15"
        reference = "https://www.ic3.gov/CSA/2026/260915.pdf"
        confidence = "medium"
        family = "CHOSEN BRICK / HEAVYGRAM"
    strings:
        $m1 = "euyrsmnszb85sf4444s" ascii wide
        $m2 = "nih6723443489kcvrf" ascii wide
        $m3 = "ytyjyujyu" ascii wide
        $m4 = "noi672pp434awkc12f" ascii wide
        $t1 = "api.telegram.org" ascii wide
        $t2 = "getUpdates" ascii wide
        $t3 = "sendDocument" ascii wide
    condition:
        filesize < 512MB and ($m1 or $m2 or $m3 or $m4) and $t1 and ($t2 or $t3)
}

rule ChosenBrick_Heavygram_Stage1_Dropper_Names
{
    meta:
        author = "Jarmi"
        description = "Stage-1 dropper that names the fake Pictory installer and the archive files the FBI lists for HEAVYGRAM"
        date = "2026-09-15"
        reference = "https://www.ic3.gov/CSA/2026/260915.pdf"
        confidence = "low"
        family = "CHOSEN BRICK / HEAVYGRAM"
    strings:
        $p1 = "Pictory_premium" ascii wide
        $f1 = "File26.zip" ascii wide
        $f2 = "downloaded_file26.txt" ascii wide
        $f3 = "SMQDServicePackages" ascii wide
    condition:
        uint16(0) == 0x5a4d and filesize < 200MB and $p1 and ($f1 or $f2 or $f3)
}

rule ChosenBrick_Heavygram_Staging_Folder_References
{
    meta:
        author = "Jarmi"
        description = "File or memory image that references the rantom.txt crypto module together with a CHOSEN BRICK staging folder name"
        date = "2026-09-15"
        reference = "https://www.ic3.gov/CSA/2026/260915.pdf"
        confidence = "low"
        family = "CHOSEN BRICK / HEAVYGRAM"
    strings:
        $r = "rantom.txt" ascii wide
        $s1 = "ssh-cache-default" ascii wide
        $s2 = "SMQDServicePackages" ascii wide
        $s3 = "MicrosoftDistribution" ascii wide
        $s4 = "MicDriver" ascii wide
    condition:
        filesize < 512MB and $r and ($s1 or $s2 or $s3 or $s4)
}
