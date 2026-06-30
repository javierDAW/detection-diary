/*
   Dire Wolf (DireWolf) ransomware - host artifact and behavior strings.
   Author: Jarmi
   Date: 2026-06-30
   Reference: https://asec.ahnlab.com/en/89944/ ; https://www.protoslabs.io/resources/deep-dive-analysis-into-dire-wolf-ransomware-ttps-and-iocs
   Notes: Anchored on durable host markers (mutex, completion marker, note name,
          extension) and the embedded recovery-denial command strings. UPX-packed
          samples should be unpacked before scanning the Go string set.
*/

rule DireWolf_Host_Markers
{
    meta:
        author = "Jarmi"
        description = "Dire Wolf ransomware host markers: mutex, completion marker, note, extension"
        date = "2026-06-30"
        reference = "https://asec.ahnlab.com/en/89944/"
        confidence = "high"
        family = "DireWolf"
    strings:
        $mutex = "Global\\direwolfAppMutex" ascii wide
        $marker = "runfinish.exe" ascii wide
        $note = "HowToRecoveryFiles.txt" ascii wide
        $ext = ".direwolf" ascii wide
        $go = "Go build ID" ascii
    condition:
        filesize < 30MB and $go and ( $mutex or $marker or $note or $ext )
}

rule DireWolf_Recovery_Commands
{
    meta:
        author = "Jarmi"
        description = "Dire Wolf embedded recovery-inhibition and log-clearing command strings"
        date = "2026-06-30"
        reference = "https://asec.ahnlab.com/en/89944/"
        confidence = "medium"
        family = "DireWolf"
    strings:
        $vss = "delete shadows /all /quiet" ascii wide
        $wb = "wbadmin delete backup" ascii wide
        $bcd = "recoveryenabled No" ascii wide
        $boot = "bootstatuspolicy ignoreallfailures" ascii wide
        $wevt = "wevtutil cl" ascii wide
        $mutex = "direwolfAppMutex" ascii wide
    condition:
        filesize < 30MB and $mutex and ( $vss or $wb or $bcd or $boot or $wevt )
}

rule DireWolf_Ransom_Note
{
    meta:
        author = "Jarmi"
        description = "Dire Wolf ransom note HowToRecoveryFiles.txt template markers"
        date = "2026-06-30"
        reference = "https://asec.ahnlab.com/en/89944/"
        confidence = "medium"
        family = "DireWolf"
    strings:
        $n1 = "HowToRecoveryFiles" ascii wide
        $n2 = "roomID" ascii wide
        $n3 = "qTox" ascii wide nocase
        $n4 = ".direwolf" ascii wide
    condition:
        filesize < 200KB and ( $n1 or $n4 ) and ( $n2 or $n3 )
}
