/*
   Qilin / Agenda / Warlock — EDR Killer multi-stage loader heuristic
   --------------------------------------------------------------------
   Two rules:
     1) Qilin_EDR_Killer_msimg32_Heuristic_2026 — heuristic match for the
        msimg32.dll loader Stage 1 (forwarder strings, Halo's Gate string
        anchors, VEH stage anchors, hasherezade provocation).
     2) Qilin_EDR_Killer_Known_Hashes_2026 — known SHA-256 anchors from
        Cisco Talos for msimg32.dll, rwdrv.sys, hlpdrv.sys and the
        Stage 4 EDR killer PE.

   Reference: https://blog.talosintelligence.com/qilin-edr-killer/
   Author:    Jarmi
   Date:      2026-05-12
*/

import "hash"

rule Qilin_EDR_Killer_msimg32_Heuristic_2026
{
    meta:
        author      = "Jarmi"
        description = "Heuristic for Qilin / Warlock msimg32.dll EDR killer loader (Halo's Gate + IAT-hooked ExitProcess + ThrottleStop BYOVD)"
        date        = "2026-05-12"
        reference   = "https://blog.talosintelligence.com/qilin-edr-killer/"
        family      = "Qilin / Agenda"
        confidence  = "medium"
        hash_known  = "7787da25451f5538766240f4a8a2846d0a589c59391e15f188aa077e8b888497"

    strings:
        // Forwarder exports back to the legitimate msimg32.dll
        $fwd1 = "AlphaBlend" ascii
        $fwd2 = "GradientFill" ascii
        $fwd3 = "TransparentBlt" ascii

        // Halo's Gate / Nt* hashing and policy table anchors
        $api1 = "NtTraceEvent" ascii
        $api2 = "NtTraceControl" ascii
        $api3 = "NtAlpcSendWaitReceivePort" ascii
        $api4 = "LdrProtectMrdata" ascii
        $api5 = "RtlDeleteFunctionTable" ascii
        $api6 = "KiUserExceptionDispatcher" ascii

        // Hardware-breakpoint / VEH abuse anchors (Stage 3)
        $hb1 = "NtOpenSection" ascii
        $hb2 = "NtMapViewOfSection" ascii
        $hb3 = "LdrpMinimalMapModule" ascii

        // Provocative DLL name pattern from Stage 3 VEH path
        $prov = "hasherezade" ascii nocase

        // PE / DOS header
        $mz = { 4D 5A }

    condition:
        $mz at 0
        and uint16(uint32(0x3C)) == 0x4550
        and filesize < 4MB
        and 2 of ($fwd*)
        and 4 of ($api*)
        and 2 of ($hb*)
        and $prov
}

rule Qilin_EDR_Killer_Known_Hashes_2026
{
    meta:
        author      = "Jarmi"
        description = "Known SHA-256 anchors for the Qilin EDR killer chain (msimg32.dll loader, rwdrv.sys ThrottleStop renamed, hlpdrv.sys helper, Stage 4 EDR killer PE)"
        date        = "2026-05-12"
        reference   = "https://blog.talosintelligence.com/qilin-edr-killer/"
        family      = "Qilin / Agenda"
        confidence  = "high"

    condition:
        filesize < 16MB and
        (
            hash.sha256(0, filesize) == "7787da25451f5538766240f4a8a2846d0a589c59391e15f188aa077e8b888497"
         or hash.sha256(0, filesize) == "16f83f056177c4ec24c7e99d01ca9d9d6713bd0497eeedb777a3ffefa99c97f0"
         or hash.sha256(0, filesize) == "bd1f381e5a3db22e88776b7873d4d2835e9a1ec620571d2b1da0c58f81c84a56"
         or hash.sha256(0, filesize) == "12fcde06ddadf1b48a61b12596e6286316fd33e850687fe4153dfd9383f0a4a0"
        )
}
