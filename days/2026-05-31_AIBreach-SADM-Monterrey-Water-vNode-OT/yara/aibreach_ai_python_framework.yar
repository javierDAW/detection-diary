/*
   YARA rules — AI-written offensive Python framework (SADM water-utility intrusion)
   Author:      Jarmi
   Date:        2026-05-31
   Family:      AI-assisted-operator-tooling (unattributed)
   References:
     - https://www.dragos.com/blog/ai-assisted-ics-attack-water-utility
     - https://gambit.security/blog-post/a-single-operator-two-ai-platforms-nine-government-agencies-the-full-technical-report

   Coverage:
     - aibreach_backuposint_framework  Recovered 17,000-line Claude-written post-compromise
                                       framework "BACKUPOSINT v9.0 APEX PREDATOR" (49 modules).
     - aibreach_ai_offensive_python    Heuristic for a large single-file Python offensive
                                       framework combining metadata, AD interrogation, and
                                       lateral-movement module markers.

   Note: the operator rotates AI-generated tooling; these are leads for recovered
   artifacts and close variants, not durable network indicators. Anchor live
   detection on the behavioral primitives (East-West to OT gateway, spray).
*/

rule aibreach_backuposint_framework
{
    meta:
        author      = "Jarmi"
        date        = "2026-05-31"
        description = "Claude-written post-compromise framework BACKUPOSINT v9.0 APEX PREDATOR banner + Python markers"
        reference   = "https://www.dragos.com/blog/ai-assisted-ics-attack-water-utility"
        family      = "AI-assisted-operator-tooling"
        confidence  = "medium"

    strings:
        $banner1 = "BACKUPOSINT" ascii nocase
        $banner2 = "APEX PREDATOR" ascii nocase
        $py1     = "import requests" ascii
        $py2     = "def main(" ascii
        $py3     = "#!/usr/bin/env python" ascii

    condition:
        filesize < 4MB
        and ($banner1 and $banner2)
        and ($py1 or $py2 or $py3)
}

rule aibreach_ai_offensive_python
{
    meta:
        author      = "Jarmi"
        date        = "2026-05-31"
        description = "Heuristic: large single-file Python offensive framework with metadata + AD + lateral-movement markers"
        reference   = "https://gambit.security/blog-post/a-single-operator-two-ai-platforms-nine-government-agencies-the-full-technical-report"
        family      = "AI-assisted-operator-tooling"
        confidence  = "low"

    strings:
        $shebang   = "#!/usr/bin/env python" ascii
        $meta_ip   = "169.254.169.254" ascii
        $ad1       = "Domain Admins" ascii
        $ad2       = "dclist" ascii
        $lat1      = "password spray" ascii nocase
        $lat2      = "credential" ascii nocase
        $sock      = "socks5" ascii nocase

    condition:
        filesize < 4MB
        and $shebang
        and $meta_ip
        and ($ad1 or $ad2)
        and ($lat1 or $lat2 or $sock)
}
