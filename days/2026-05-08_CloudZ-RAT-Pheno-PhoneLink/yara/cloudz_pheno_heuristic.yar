/*
   Title:        CloudZ_Pheno_Heuristic_2026
   Author:       Jarmi
   Date:         2026-05-08
   Reference:    Cisco Talos blog post on CloudZ + Pheno infostealer
   Description:  Heuristic for CloudZ .NET RAT and the Pheno plugin that hijacks
                 Microsoft Phone Link to harvest mirrored SMS and OTP messages.
                 Anchors: ConfuserEx packing markers, Phone Link package paths,
                 Cloudflare Workers C2 domain fragment, the HELLOHIALL handle,
                 dynamic-IL emit primitives, embedded SQLite client.
   Confidence:   medium
   Family:       CloudZ / Pheno
*/

import "pe"

rule CloudZ_Pheno_Heuristic_2026
{
    meta:
        author = "Jarmi"
        description = "Heuristic for CloudZ RAT and Pheno Phone Link OTP harvester (Talos, May 2026)"
        date = "2026-05-08"
        reference = "https://blog.talosintelligence.com/cloudz-pheno-infostealer/"
        confidence = "medium"
        family = "CloudZ"

    strings:
        $confuser1      = "ConfuserEx" ascii wide
        $confuser2      = { 3C 4D 6F 64 75 6C 65 3E 7B }
        $phonelink_pkg  = "Microsoft.YourPhone_8wekyb3d8bbwe" ascii wide
        $phonelink_db   = "PhoneExperiences" ascii wide
        $proc_yourphone = "PhoneExperienceHost" ascii wide
        $proc_yourphone2= "YourPhone" ascii wide
        $hellohiall     = "HELLOHIALL" ascii wide
        $workers_dev    = "hellohiall.workers.dev" ascii wide
        $dyn_emit_1     = "System.Reflection.Emit.DynamicMethod" ascii wide
        $dyn_emit_2     = "ILGenerator" ascii wide
        $profiling_env  = "_ENABLE_PROFILING" ascii wide
        $sqlite_lib     = "Microsoft.Data.Sqlite" ascii wide

    condition:
        uint16(0) == 0x5A4D
        and filesize < 10MB
        and pe.imports("mscoree.dll")
        and (
            (
                ( $phonelink_pkg or $phonelink_db or $proc_yourphone or $proc_yourphone2 )
                and ( $hellohiall or $workers_dev or $sqlite_lib )
            )
            or
            (
                ( any of ($confuser*) )
                and ( $profiling_env or all of ($dyn_emit_*) )
                and ( $hellohiall or $workers_dev )
            )
        )
}
