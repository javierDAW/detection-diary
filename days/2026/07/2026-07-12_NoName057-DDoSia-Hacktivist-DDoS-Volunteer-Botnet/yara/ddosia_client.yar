/*
   NoName057(16) DDoSia (Go-Stresser) client and kit heuristics.
   Author: Jarmi  Date: 2026-07-12
   Structure/string heuristics for defensive triage of a suspected DDoSia volunteer
   host, an analyst workstation, or a captured memory/pcap artifact. The operators
   recompile the Go client frequently (per-build hashes rotate), so these rules match
   the durable protocol strings, the fixed C2 URIs and the kit layout - NOT a single
   confirmed sample hash. Bound by filesize. Reference: Sekoia TDR DDoSia analysis.
*/

rule DDoSia_GoStresser_Client
{
    meta:
        author = "Jarmi"
        description = "NoName057(16) DDoSia Go client: C2 URIs, custom headers and self-branding banner"
        date = "2026-07-12"
        reference = "https://blog.sekoia.io/following-noname05716-ddosia-projects-targets"
        confidence = "medium"
        family = "ddosia"
    strings:
        $u1 = "/client/get_targets" ascii
        $u2 = "/client/login" ascii
        $h1 = "Client-Hash" ascii
        $h2 = "User-Hash" ascii
        $b1 = "Go-Stresser" ascii
        $b2 = "NoName057(16)" ascii
        $go = "Go build ID" ascii
    condition:
        filesize < 40MB and
        ( ($u1 and $u2) or
          ($u1 and ($h1 or $h2)) or
          ($b1 or $b2) or
          ($go and $u1 and $h1) )
}

rule DDoSia_Target_Config_Decrypted
{
    meta:
        author = "Jarmi"
        description = "Decrypted DDoSia target-list JSON in memory/pcap: target metadata fields and cache-buster randoms"
        date = "2026-07-12"
        reference = "https://blog.sekoia.io/following-noname05716-ddosia-projects-targets"
        confidence = "low"
        family = "ddosia-config"
    strings:
        $j1 = "\"target_id\"" ascii
        $j2 = "\"request_id\"" ascii
        $j3 = "\"use_ssl\"" ascii
        $j4 = "\"randoms\"" ascii
        $j5 = "\"targets\"" ascii
    condition:
        filesize < 20MB and
        ( ($j1 and $j2) or
          ($j5 and $j3) or
          ($j4 and $j5) )
}

rule DDoSia_Volunteer_Kit_Artifacts
{
    meta:
        author = "Jarmi"
        description = "DDoSia volunteer kit layout: per-OS client filenames, bcrypt id file and help.txt inside d.zip"
        date = "2026-07-12"
        reference = "https://blog.sekoia.io/following-noname05716-ddosia-projects-targets"
        confidence = "low"
        family = "ddosia-kit"
    strings:
        $f1 = "d_windows_amd64.exe" ascii
        $f2 = "d_linux_amd64" ascii
        $f3 = "d_mac_arm64" ascii
        $id = "$2a$16$" ascii
        $help = "help.txt" ascii
    condition:
        filesize < 50MB and
        ( ($f1 and $f2) or
          ($f1 and $f3) or
          ($id and ($f1 or $f2 or $help)) )
}
