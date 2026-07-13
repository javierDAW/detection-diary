/*
   UAT-7810 (LapDogs ORB) malware-suite structure heuristics.
   Author: Jarmi  Date: 2026-07-13
   Reference: https://blog.talosintelligence.com/uat-7810/
   Defensive triage of ELF/JAR artifacts recovered from a suspected ORB relay node
   (Ruckus / SOHO router, or a compromised Linux host). UAT-7810 recompiles per
   architecture (MIPS/ARM/x64) and per variant, so per-build hashes rotate; these rules
   match the DURABLE internal names, the embedded Chrome-122 User-Agent decoy, the LEASHTEST
   test strings and the self-signed TLS cert identity - NOT a single confirmed sample.
   All bounded by filesize. Comments in English.
*/

rule UAT7810_LONGLEASH_ffagent
{
    meta:
        author = "Jarmi"
        description = "LONGLEASH/SHORTLEASH (ff-agent) ORB implant: internal project names plus embedded Chrome 122 User-Agent decoy"
        date = "2026-07-13"
        reference = "https://blog.talosintelligence.com/uat-7810/"
        confidence = "medium"
        family = "longleash"
    strings:
        $n1 = "ff-agent" ascii
        $n2 = "nz1.0" ascii
        $ua = "Chrome/122.0.6261.95 Safari/537.36" ascii
        $l1 = "Boost.Asio" ascii
        $l2 = "nanopb" ascii nocase
        $l3 = "mbedtls" ascii nocase
    condition:
        uint32(0) == 0x464c457f and filesize < 8MB and
        ( ($n1 and $n2) or
          ($n1 and $ua) or
          ($n2 and ($l1 or $l2 or $l3)) )
}

rule UAT7810_LEASHTEST_iot_test
{
    meta:
        author = "Jarmi"
        description = "LEASHTEST MIPS functionality-test ELF (internal name iot-test): benign alone, indicates UAT-7810 activity on the device"
        date = "2026-07-13"
        reference = "https://blog.talosintelligence.com/uat-7810/"
        confidence = "low"
        family = "leashtest"
    strings:
        $t1 = "iot-test" ascii
        $t2 = "Hello World!" ascii
        $t3 = "async timer" ascii nocase
        $t4 = "acceptor" ascii nocase
    condition:
        uint32(0) == 0x464c457f and filesize < 4MB and
        ( ($t1 and $t2) or
          ($t1 and $t3) or
          ($t1 and $t4) )
}

rule UAT7810_ORB_deploy_and_cert
{
    meta:
        author = "Jarmi"
        description = "UAT-7810 deployment shell scripts and self-signed TLS cert identity: DOGLEASH loader (iptables open + fetch), JARLEASH kill/spawn, CN=exploit cert subject"
        date = "2026-07-13"
        reference = "https://blog.talosintelligence.com/uat-7810/"
        confidence = "low"
        family = "uat7810-infra"
    strings:
        $s1 = "iptables" ascii
        $s2 = "-j ACCEPT" ascii
        $s3 = "CN=exploit" ascii
        $s4 = "OU=exploit" ascii
        $s5 = ":8088/" ascii
        $s6 = ":2222/" ascii
    condition:
        filesize < 512KB and
        ( ($s3 and $s4) or
          ($s1 and $s2 and ($s5 or $s6)) )
}
