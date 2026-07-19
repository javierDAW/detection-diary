rule INC_Ransomware_Note_And_Persistence_Artifacts
{
    meta:
        author = "Jarmi"
        description = "Detects documented INC Ransomware (S1139 / GOLD IONIC / G1032) ransom-note artifacts, base64 note-decode routine, and persistence/service-masquerade strings. Built from publicly documented indicators (SentinelOne, Cybereason, Trend Micro), not a hash-verified sample specific to the Acworth incident."
        date = "2026-07-19"
        reference = "https://www.sentinelone.com/anthology/inc-ransom/"
        confidence = "medium"
        family = "INC Ransomware"

    strings:
        $note_txt = "INC-README.txt" ascii wide
        $note_html = "INC-README.html" ascii wide
        $ext_inc = ".INC" ascii wide
        $sched_task = "INC_Update" ascii wide
        $svc_masquerade = "winupd.exe" ascii wide
        $api_decode = "CryptStringToBinaryA" ascii
        $api_shadow = "DeviceIoControl" ascii
        $tool_psexec = "PSEXESVC" ascii wide
        $tool_netscan = "NETSCAN.EXE" ascii wide nocase

    condition:
        filesize < 15MB and
        (
            ($note_txt or $note_html) or
            ($ext_inc and $sched_task) or
            ($ext_inc and $svc_masquerade) or
            ($sched_task and $svc_masquerade) or
            ($api_decode and $api_shadow and ($tool_psexec or $tool_netscan))
        )
}
