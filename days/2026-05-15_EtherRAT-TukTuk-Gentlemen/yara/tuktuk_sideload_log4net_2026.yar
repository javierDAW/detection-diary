/*
 * TukTuk side-loaded log4net stub — heuristic plus known-hash anchor
 *
 * Reference: https://thedfirreport.com/2026/05/11/flash-alert-etherrat-and-tuktuk-c2-end-in-the-gentleman-ransomware/
 * Family:    TukTuk
 * Author:    Jarmi
 * Date:      2026-05-15
 *
 * The heuristic rule combines .NET CLR magic, the impersonation string log4net, three or
 * more multi-transport bus anchors (ClickHouse, Supabase, Ably, Dropbox API, GitHub
 * Issues), and at least one Arweave dead-drop anchor (arweave.net, g8way.io, or the
 * literal Drive-Id). Size capped at 5 MB to suppress matches against unrelated large
 * binaries that ship multiple SaaS SDK strings.
 */

import "hash"

rule TukTuk_log4net_sideload_2026
{
    meta:
        author      = "Jarmi"
        description = "Heuristic for TukTuk side-loaded fake log4net.dll observed by The DFIR Report May 2026"
        date        = "2026-05-15"
        reference   = "https://thedfirreport.com/2026/05/11/flash-alert-etherrat-and-tuktuk-c2-end-in-the-gentleman-ransomware/"
        confidence  = "medium"
        family      = "TukTuk"
    strings:
        $mz       = { 4D 5A }
        $clr      = "BSJB"                    // .NET metadata magic at start of CLR header

        // Multi-transport pluggable bus anchors
        $t1       = "clickhouse.cloud"     ascii wide
        $t2       = "supabase.co"          ascii wide
        $t3       = "ably.io"              ascii wide
        $t4       = "api.dropboxapi.com"   ascii wide
        $t5       = "api.github.com/repos" ascii wide

        // Arweave dead-drop resolver anchors
        $arweave1 = "arweave.net"          ascii wide
        $arweave2 = "g8way.io"             ascii wide
        $drive    = "Drive-Id"             ascii wide

        // log4net impersonation marker
        $fake     = "log4net"              ascii wide
    condition:
        $mz at 0 and $clr and $fake and
        (3 of ($t*)) and
        (any of ($arweave*) or $drive) and
        filesize < 5MB
}

rule TukTuk_log4net_known_hashes_2026
{
    meta:
        author      = "Jarmi"
        description = "Exact SHA256 anchor for the TukTuk log4net.dll reported by The DFIR Report TB40048"
        date        = "2026-05-15"
        reference   = "https://thedfirreport.com/2026/05/11/flash-alert-etherrat-and-tuktuk-c2-end-in-the-gentleman-ransomware/"
        confidence  = "high"
        family      = "TukTuk"
    condition:
        hash.sha256(0, filesize) == "19021e53b9929fdf4b7d0e0707434d56bb73c1a9b7403c8837b44d1c417198dc"
}
