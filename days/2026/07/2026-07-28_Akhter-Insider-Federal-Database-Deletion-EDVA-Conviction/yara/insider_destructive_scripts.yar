/*
   Detection Diary -- Day 92 -- Akhter federal-database-deletion insider case (EDVA, 2026)
   Author: Jarmi
   These are HUNTING rules for destructive-insider scripts/artifacts, not malware family
   signatures. There is no public malware sample in this case; the rules target the durable
   text patterns of a mass-database-destruction / anti-forensics batch left on a host or in a
   collected script repository. Tune before enabling on developer / DBA workstations.
*/

rule Insider_Mass_Database_Drop_Script
{
    meta:
        author = "Jarmi"
        description = "Script or batch containing repeated destructive database verbs (DROP DATABASE / DETACH) consistent with mass data-destruction by an insider"
        date = "2026-07-28"
        reference = "https://www.justice.gov/opa/pr/federal-jury-convicts-virgina-man-charges-relating-deletion-us-government-databases"
        confidence = "heuristic"
        family = "Insider-DataDestruction"
    strings:
        $drop_db     = "DROP DATABASE" ascii nocase
        $detach_sp   = "sp_detach_db" ascii nocase
        $detach_stmt = "DETACH DATABASE" ascii nocase
        $mongo_drop  = "dropDatabase(" ascii nocase
        $sqlcmd      = "sqlcmd" ascii nocase
        $forloop     = "for /f" ascii nocase
    condition:
        filesize < 200KB and
        (
            ($drop_db and #drop_db >= 2) or
            ($detach_sp and $sqlcmd) or
            ($detach_stmt and $forloop) or
            ($mongo_drop and $forloop)
        )
}

rule Insider_AntiForensics_Wipe_Script
{
    meta:
        author = "Jarmi"
        description = "Script combining database/backup deletion with Windows event-log or USN-journal clearing -- destruction plus evidence removal in one artifact"
        date = "2026-07-28"
        reference = "https://www.justice.gov/opa/pr/federal-jury-convicts-virgina-man-charges-relating-deletion-us-government-databases"
        confidence = "heuristic"
        family = "Insider-DataDestruction"
    strings:
        $wevtutil   = "wevtutil" ascii nocase
        $clearlog   = "Clear-EventLog" ascii nocase
        $usnwipe    = "deletejournal" ascii nocase
        $del_mdf    = ".mdf" ascii nocase
        $del_bak    = ".bak" ascii nocase
        $del_verb   = "del " ascii nocase
        $rm_verb    = "Remove-Item" ascii nocase
    condition:
        filesize < 200KB and
        (
            ($wevtutil or $clearlog or $usnwipe) and
            ($del_mdf or $del_bak) and
            ($del_verb or $rm_verb)
        )
}
