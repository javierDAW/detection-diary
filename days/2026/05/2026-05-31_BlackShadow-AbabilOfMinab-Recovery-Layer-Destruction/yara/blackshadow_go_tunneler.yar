/*
   YARA rules — Black Shadow / Ababil of Minab (Iran-MOIS) tooling
   Author:      Jarmi
   Date:        2026-05-31
   Family:      Black Shadow (customized Go tunneler "A.ExE")
   References:
     - https://gambit.security/blog-posts/babil-of-minab-iran-mois-destruction-campaign
     - https://industrialcyber.co/industrial-cyber-attacks/gambit-links-iran-linked-black-shadow-group-to-destructive-cyber-campaign-targeting-us-middle-east-organizations/

   Note: full hashes were not published in the coverage reviewed (truncated
   prefixes f6db77b / 1c69972 / 38965a6). These rules anchor on Go-tunneler
   structure plus campaign C2 strings; treat as leads, refresh from intel.
*/

rule blackshadow_go_tunneler
{
    meta:
        author      = "Jarmi"
        date        = "2026-05-31"
        description = "Customized public Go tunneler (A.ExE) with Black Shadow C2 / persona markers"
        reference   = "https://gambit.security/blog-posts/babil-of-minab-iran-mois-destruction-campaign"
        family      = "BlackShadow"
        confidence  = "medium"

    strings:
        $go1     = "Go build ID:" ascii
        $go2     = "runtime.goexit" ascii
        $c2_host = "nefeshhope.com" ascii nocase
        $c2_ip   = "46.30.190.173" ascii
        $infra   = "45.150.108.61" ascii
        $tunnel1 = "socks5" ascii nocase
        $tunnel2 = "-listen" ascii

    condition:
        filesize < 30MB
        and ($go1 or $go2)
        and ($c2_host or $c2_ip or $infra)
        and ($tunnel1 or $tunnel2)
}

rule blackshadow_persona_markers
{
    meta:
        author      = "Jarmi"
        date        = "2026-05-31"
        description = "Black Shadow / Ababil of Minab persona and destruction-script markers"
        reference   = "https://gambit.security/blog-posts/babil-of-minab-iran-mois-destruction-campaign"
        family      = "BlackShadow"
        confidence  = "low"

    strings:
        $p1   = "Ababil of Minab" ascii nocase
        $p2   = "Minab" ascii
        $wipe = "WipeFile" ascii
        $sql1 = "DROP DATABASE" ascii nocase
        $sql2 = "SET OFFLINE" ascii nocase

    condition:
        filesize < 5MB
        and ($p1 or ($p2 and ($wipe or $sql1 or $sql2)))
}
