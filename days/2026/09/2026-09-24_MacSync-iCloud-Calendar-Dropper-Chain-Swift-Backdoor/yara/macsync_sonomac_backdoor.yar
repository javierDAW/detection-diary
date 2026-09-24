/*
  MacSync (Kaspersky Securelist 2026-09-24) - macOS infostealer and Finder-disguised backdoor
  Author: Jarmi
  Date: 2026-09-24
  Reference: https://securelist.com/macsync-new-version/121383/

  Scope and honesty note
  - No sample was available for this entry. The rules are built only from strings that Kaspersky publishes: the SONOMAC1 overlay
    magic, the stage 1 XOR key, the backdoor C2 paths and header names, and the backdoor command names.
  - Most stages are encrypted (XOR, AES-CBC, zlib), so strings that live inside an encrypted blob are NOT expected on disk. Rule 1
    targets the stage 1 loader whose key and magic must be readable; rules 2 and 3 are meant for decrypted stages in memory dumps,
    for the backdoor Mach-O after it is written, and for recovered stage 5 and stage 6 scripts.
  - Whether the XOR key sits in the loader as a literal is not stated; the key rule is OR-combined with the magic word so that the
    rule still fires if only one of them is present as a plain string.
  - Confidence is medium or low. Hash matching (iocs.csv, MD5 only) is the reliable detection for the published samples.
*/

rule MacSync_Stage1_Loader_Overlay_Markers
{
    meta:
        author = "Jarmi"
        description = "Mach-O carrying the MacSync stage 1 overlay magic SONOMAC1 or the published stage 1 XOR key"
        date = "2026-09-24"
        reference = "https://securelist.com/macsync-new-version/121383/"
        confidence = "medium"
        family = "MacSync"
    strings:
        $magic = "SONOMAC1" ascii
        $xorkey = { 73 6F 6E 6F 6D 61 62 6C 64 07 }
    condition:
        (uint32(0) == 0xFEEDFACF or uint32(0) == 0xBEBAFECA or uint32(0) == 0xFEEDFACE) and filesize < 100MB and ($magic or $xorkey)
}

rule MacSync_Backdoor_C2_Protocol_Strings
{
    meta:
        author = "Jarmi"
        description = "Mach-O or memory image with the MacSync backdoor C2 paths, upload header and persistence names"
        date = "2026-09-24"
        reference = "https://securelist.com/macsync-new-version/121383/"
        confidence = "medium"
        family = "MacSync"
    strings:
        $h1 = "X-Upload-Token" ascii
        $h2 = "X-File-Sha256" ascii
        $e1 = "/v1/agent/ping" ascii
        $e2 = "/v1/agent/refresh" ascii
        $e3 = "/v1/asset/" ascii
        $p1 = "--persist-status" ascii
        $p2 = "LAUNCHER_DEBUG" ascii
        $p3 = ".sysnotif-agent.log" ascii
        $p4 = "com.apple.finder.agent" ascii
        $c1 = "AGNT1" ascii
    condition:
        (uint32(0) == 0xFEEDFACF or uint32(0) == 0xBEBAFECA or uint32(0) == 0xFEEDFACE) and filesize < 50MB and $h1 and ($e1 or $e2 or $e3) and ($h2 or $p1 or $p2 or $p3 or $p4 or $c1)
}

rule MacSync_Agent_Commands_And_Key_Derivation
{
    meta:
        author = "Jarmi"
        description = "Script, Mach-O or memory image naming MacSync backdoor commands or the stage 5 and 6 key-derivation fields"
        date = "2026-09-24"
        reference = "https://securelist.com/macsync-new-version/121383/"
        confidence = "low"
        family = "MacSync"
    strings:
        $k1 = "sn-dek-wrap-v1" ascii
        $k2 = "dek_wrap_b64" ascii
        $k3 = "build_pub_b64" ascii
        $m1 = "deploy_ledger" ascii
        $m2 = "deploy_ext" ascii
        $m3 = "regrab" ascii
        $m4 = "live_browser" ascii
        $m5 = "sn_relay" ascii
        $m6 = "script_b64" ascii
        $m7 = "upload_token" ascii
        $z1 = "osalogging.zip" ascii
    condition:
        filesize < 50MB and (($k1 and ($k2 or $k3)) or ($m1 and $m2 and ($m3 or $m4 or $m5)) or ($m6 and $m7 and ($m1 or $m2 or $m3 or $m4 or $m5 or $z1)))
}
