/*
   YARA rules — Cisco Catalyst SD-WAN post-compromise implants observed by Talos in
   ten activity clusters following the mass exploitation of CVE-2026-20133, CVE-2026-20128
   and CVE-2026-20122 (Cisco SD-WAN Manager, vManage chain) since March 2026, and the
   targeted UAT-8616 exploitation of CVE-2026-20127 / CVE-2026-20182 (vSmart controller).
   Reference: https://blog.talosintelligence.com/sd-wan-ongoing-exploitation/
   Author: Jarmi — 2026-05-16
*/

rule SDWAN_AdaptixC2_Implant_Shadowcore_2026
{
    meta:
        author = "Jarmi"
        date = "2026-05-16"
        description = "AdaptixC2-based implant deployed in Talos Cluster 5 on compromised Catalyst SD-WAN appliances. Default 'AdapticC2 server' banner is renamed to 'shadowcore' to evade signature-based detection."
        reference = "https://blog.talosintelligence.com/sd-wan-ongoing-exploitation/"
        confidence = "high"
        family = "AdaptixC2"
        sha256 = "f6f8e0d790645395188fc521039385b7c4f42fa8b426fd035f489f6cda9b5da1"

    strings:
        $elf_magic = { 7F 45 4C 46 }
        $banner_shadowcore = "shadowcore" ascii nocase
        $adaptix_default_banner = "AdapticC2" ascii nocase
        $impl_name1 = "systemd-resolved" ascii
        $c2_ip1 = "194.163.175.135" ascii
        $c2_port = ":4445" ascii
        $known_hash_anchor1 = { 73 79 73 74 65 6D 64 2D 72 65 73 6F 6C 76 65 64 }   // "systemd-resolved"

    condition:
        $elf_magic at 0
        and filesize < 50MB
        and (
            $banner_shadowcore
            or ($adaptix_default_banner and ($impl_name1 or $c2_ip1 or $c2_port))
            or ($known_hash_anchor1 and ($c2_ip1 or $c2_port))
        )
}

rule SDWAN_NimImplant_AgentOne_2026
{
    meta:
        author = "Jarmi"
        date = "2026-05-16"
        description = "Nim-based implant 'agent1' dropped in Talos Cluster 8 on compromised Catalyst SD-WAN systems. Likely AI-modified clone of NimPlant exposing custom REST endpoints under /api/v1/* on C2 13.62.52.206:5004. Downloaded post-exploit from a Replit-hosted dropper."
        reference = "https://blog.talosintelligence.com/sd-wan-ongoing-exploitation/"
        confidence = "high"
        family = "NimPlant-variant"
        sha256 = "0c87871642f84e09e8d3fb23ec36bf55601323e31151a7017a85dbec929cf15d"

    strings:
        $elf_magic = { 7F 45 4C 46 }
        $nim_anchor1 = "NimPlant" ascii nocase
        $nim_anchor2 = "@nimrt" ascii nocase
        $nim_anchor3 = "fatal.nim" ascii nocase
        $api_v1_handshake = "/api/v1/handshake" ascii
        $api_v1_results = "/api/v1/results" ascii
        $api_v1_payloads = "/api/v1/payloads" ascii
        $api_v1_exfil = "/api/v1/exfiltrate" ascii
        $api_v1_tasks = "/api/v1/tasks" ascii
        $api_v1_init = "/api/v1/init" ascii
        $c2_host = "13.62.52.206" ascii
        $replit_dropper = "replit.dev" ascii

    condition:
        $elf_magic at 0
        and filesize < 30MB
        and (
            (2 of ($nim_anchor*) and 2 of ($api_v1_*))
            or ($c2_host and 1 of ($api_v1_*))
            or ($replit_dropper and 2 of ($api_v1_*))
        )
}
