/*
   RedLamassu_JFMBackdoor_Showboat_2026.yar
   YARA rules for the Red Lamassu / Calypso toolkit disclosed by PwC TI and
   Lumen Black Lotus Labs on 2026-05-21. Two heuristic rules anchor on:
     1. JFMBackdoor — Windows PE side-loaded via FLTLIB.dll, with the
        hardcoded XOR key Zs0@31=KDw.*7ev, the C:\Users\public\jfm path
        anchor, and CppServer class strings TCPSession/WSSession/WSSSession.
     2. Showboat / kworker — Linux ELF post-exploitation framework with the
        cheeky XOR key "look me, AV!" and the SOCKS5 / portmap function
        markers.
   Plus one known-hash rule for the open-directory artefacts published by
   PwC TI on 2026-05-21.
   Author: Jarmi
*/

import "hash"

rule RedLamassu_JFMBackdoor_PE_Heuristic_2026
{
    meta:
        author      = "Jarmi"
        description = "Heuristic for JFMBackdoor Windows PE delivered via FLTLIB.dll side-load (PwC TI, 2026-05-21)"
        date        = "2026-05-22"
        reference   = "https://www.pwc.com/gx/en/issues/cybersecurity/cyber-threat-intelligence/red-lamassu-open-season.html"
        confidence  = "high"
        family      = "JFMBackdoor / Red Lamassu / Calypso"

    strings:
        // Hardcoded XOR key used to decrypt scr.mui config
        $xor_key      = "Zs0@31=KDw.*7ev" ascii
        // Hardcoded internal path that gave the family its name
        $jfm_path     = "C:\\Users\\public\\jfm" ascii nocase
        // CppServer class names used for C2 transports
        $cls_tcp      = "TCPSession" ascii
        $cls_ws       = "WSSession" ascii
        $cls_wss      = "WSSSession" ascii
        // C2 anchors
        $dom_a        = "namefuture.site" ascii nocase
        $dom_b        = "cumm.info" ascii nocase
        $dom_c        = "xcent.online" ascii nocase
        // Side-load artefacts referenced inside the implant config
        $art_flt      = "flt.bin" ascii
        $art_scr      = "scr.mui" ascii
        $art_fltlib   = "FLTLIB.dll" ascii nocase

    condition:
        uint16(0) == 0x5A4D
        and filesize < 4MB
        and (
            ($xor_key and 1 of ($cls_*))
            or ($jfm_path and 1 of ($cls_*))
            or ($xor_key and 2 of ($art_*))
            or (1 of ($dom_*) and 1 of ($cls_*) and 1 of ($art_*))
        )
}

rule RedLamassu_Showboat_ELF_Heuristic_2026
{
    meta:
        author      = "Jarmi"
        description = "Heuristic for Showboat / kworker Linux ELF post-exploitation framework (Lumen Black Lotus Labs, 2026-05-21)"
        date        = "2026-05-22"
        reference   = "https://www.lumen.com/blog/en-us/introducing-showboat-a-new-malware-family-taunts-defenses-and-targets-international-telecom-firms"
        confidence  = "high"
        family      = "Showboat / kworker / Red Lamassu / Calypso"

    strings:
        // Cheeky XOR key used to decrypt the embedded config
        $xor_taunt    = "look me, AV!" ascii
        // Internal function suffixes for SOCKS5 and portmap URL construction
        $sks_marker   = "SKS" ascii
        $map_marker   = "MAP" ascii
        // Process name masquerade
        $kworker      = "kworker" ascii
        // C2 anchors
        $dom_a        = "telecom.webredirect.org" ascii nocase
        $dom_b        = "kaztelecom.shop" ascii nocase
        $dom_c        = "singtelcom.site" ascii nocase
        $dom_d        = "newsprojects.online" ascii nocase
        // Configuration field names embedded in the implant
        $cfg_addr     = "SERVER_ADDRESS" ascii
        $cfg_min      = "MIN_SLEEP" ascii
        $cfg_slow     = "SLOW_MODE_MIN_SLEEP" ascii

    condition:
        uint32(0) == 0x464C457F
        and filesize < 8MB
        and (
            ($xor_taunt and $kworker)
            or ($cfg_addr and $cfg_min and $cfg_slow and $kworker)
            or ($kworker and 1 of ($dom_*) and ($sks_marker or $map_marker))
        )
}

rule RedLamassu_OpenDirectory_KnownHashes_2026
{
    meta:
        author      = "Jarmi"
        description = "Known-hash anchors for the Red Lamassu open-directory artefacts (PwC TI, 2026-05-21)"
        date        = "2026-05-22"
        reference   = "https://github.com/PwCUK-CTO/TI-blog-2026-Red-Lamassu-JFMBackdoor"
        confidence  = "high"
        family      = "Red Lamassu / Calypso open directory"

    condition:
        // Files staged on 23.27.201[.]160 between July and October 2025
        hash.sha256(0, filesize) == "a05fbe8734a5a5a994a44dee9d21134ad7108d24ab0749499fe24fc4b36c4cbc"   // systemd-ac-update (kworker)
        or hash.sha256(0, filesize) == "047307aca3a94a6fc46c4af25580945defb15574fb236d13d2bb48037cc42208" // FLTLIB.dll
        or hash.sha256(0, filesize) == "ac50887e2c513b50b2170d77441b9f7e8afcc774df6b54fdd8aac863095239f4" // clear
        or hash.sha256(0, filesize) == "a23d126f0446755859e4d81c0c9b50b65e0062c3de2a014c543f6b263321ad78" // 1.bat
        or hash.sha256(0, filesize) == "ea57b5768c84164fcdb25bb8338d660c5586e17e37cee924c4e5a745510925f3" // scr.mui
        or hash.sha256(0, filesize) == "cbef2064cf49b4b27dbf7d0c88c8f7bcdd6a7f25ee9c087beacb48cdd1b78731" // fltMC.exe
        or hash.sha256(0, filesize) == "b77a233735ff237ab964d2bdb3f6d261a90efb2f86dcde458c419cee528686a9" // flt.bin
        or hash.sha256(0, filesize) == "176aec5d33c459a42e7e4e984a718c52e11213ef9a6aa961b483a836fc22b507" // JFMBackdoor PE
        or hash.sha256(0, filesize) == "b118f74dc2b974678a50349d04686f6b2df4b287a69e40c4513cd603c7271793" // CiWinCng32.dll variant
        or hash.sha256(0, filesize) == "1003bc9e3650fd290e44fd79b270c1b29f572fbb7647fa2bbf1f600d53673b53" // scr.mui variant
        or hash.sha256(0, filesize) == "f820e4e4c5d433714842f6d64d1a8773958f782cde8d27f6a54d4f9862598933" // sllauncherloc.dll variant
}
