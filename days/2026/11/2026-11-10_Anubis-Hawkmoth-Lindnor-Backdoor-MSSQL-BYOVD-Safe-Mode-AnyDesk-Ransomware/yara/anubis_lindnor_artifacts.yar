/*
   Anubis (Hawkmoth RaaS) intrusion with the Lindnor backdoor - ransom artefacts and AnyDesk Safe Mode tooling
   Author: Jarmi
   Date: 2026-11-10
   Reference: Symantec (Broadcom) 2026-11-05
              https://www.security.com/threat-intelligence/lindnor-new-backdoor-anubis-ransomware
              (relayed by GBHackers and Cyber Security News 2026-11-09)
   Honesty: derived from the Symantec report as relayed; no first-hand sample analysis. No byte
   patterns, strings or packer details of the samples are published, so these rules only use the
   literals printed in the report (the ".anubis" extension, the ransom note names "restore files.txt" /
   "restore files.html" with spacing as printed, and the verbatim SafeBoot registry command). They were
   NOT verified against samples; the payload may build these strings at runtime. "CSIDL_SYSTEM" in the
   printed command is the report's placeholder for the System32 folder and is deliberately NOT required.
   Prefer the SHA-256 list (below / kql/k2) for high-fidelity matching. Indicators decay.
   Scan targets: SQL Server hosts, ProgramData / Temp / user profiles, sandbox drops, memory dumps.
   Reference hashes (NOT used in conditions):
     iservice.exe (Anubis)  e69b882218fa2a19fd351741874bfcd10a6ae91076e6a8483795e0e357f8d026
     safemode.exe           47a864736764112d7897c76e56d51111ce75b3e46fdbac6933df8a5b29507d17
     Lindnor                fc200686175559f4544a5de826905f09a68476d889690a3be40ac32356790cb8
     Lindnor                5d2dd9caf2ae4a5083dbec16e688040456cdbc31eaeecbab78188e322ed0415b
     Lindnor                ad9575a9ef2dcc9d2fd2a24376c418549d4b3db5564c22b20081d33cf7629e43
*/

rule Anubis_Ransomware_Note_And_Extension_Strings
{
    meta:
        author = "Jarmi"
        description = "Anubis (Hawkmoth RaaS) payload or dropper carrying the .anubis extension together with a ransom note name (restore files.txt / restore files.html) as printed by Symantec; low confidence, strings unverified against samples"
        date = "2026-11-10"
        reference = "https://www.security.com/threat-intelligence/lindnor-new-backdoor-anubis-ransomware"
        confidence = "low"
        family = "Anubis"
    strings:
        $ext_a = ".anubis" ascii nocase
        $ext_w = ".anubis" wide nocase
        $note_txt_a = "restore files.txt" ascii nocase
        $note_txt_w = "restore files.txt" wide nocase
        $note_htm_a = "restore files.html" ascii nocase
        $note_htm_w = "restore files.html" wide nocase
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        ($ext_a or $ext_w) and
        ($note_txt_a or $note_txt_w or $note_htm_a or $note_htm_w)
}

rule Anubis_SafeMode_AnyDesk_SafeBoot_Registration
{
    meta:
        author = "Jarmi"
        description = "Binary or script that registers AnyDesk under SafeBoot\\Network so it starts in Safe Mode with Networking (safemode.exe behaviour in the Anubis intrusion): SafeBoot Network AnyDesk key path plus reg.exe add / default value / Service data fragments of the verbatim command"
        date = "2026-11-10"
        reference = "https://www.security.com/threat-intelligence/lindnor-new-backdoor-anubis-ransomware"
        confidence = "medium"
        family = "Anubis-safemode-tool"
    strings:
        $key_a = "SafeBoot\\Network\\AnyDesk" ascii nocase
        $key_w = "SafeBoot\\Network\\AnyDesk" wide nocase
        $reg_a = "reg.exe" ascii nocase
        $reg_w = "reg.exe" wide nocase
        $ve_a = "/ve /t REG_SZ /d Service" ascii nocase
        $ve_w = "/ve /t REG_SZ /d Service" wide nocase
        $ccs_a = "CurrentControlSet\\Control\\SafeBoot" ascii nocase
        $ccs_w = "CurrentControlSet\\Control\\SafeBoot" wide nocase
    condition:
        filesize < 10MB and
        ($key_a or $key_w) and
        ($reg_a or $reg_w or $ve_a or $ve_w or $ccs_a or $ccs_w)
}
