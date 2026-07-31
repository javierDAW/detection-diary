// YARA rules for the V25 / Generation 26 covert XMRig fileless miner (Group-IB, 2026-07-30).
// Strings target the modified XMRig 6.25.0 build (musl) and its decrypted config markers.
// Intended for memory scanning as well as on-disk: the binary self-unlinks after taking /tmp/.lock.

rule XMRig_V25_Private_Botnet_Banner
{
    meta:
        author = "Jarmi"
        description = "Modified XMRig 6.25.0 fork branded PRIVATE VERSION FOR BOTNET with V25/Generation-26 campaign markers"
        date = "2026-07-31"
        reference = "https://www.group-ib.com/blog/xmrig-covert-linux-pam-abuse/"
        confidence = "high"
        family = "XMRig-V25-GEN-26"
        hash = "55c67c844258807c4335f40262777a5307bcf5b537c0492cf869b3328796f838"
    strings:
        $banner   = "PRIVATE VERSION FOR BOTNET" ascii
        $gen_user = "My-V25-GEN-26" ascii
        $gen_pass = "V25-GEN-26" ascii
        $pool     = "unable.download" ascii
        $xmrig    = "XMRig/6.25.0" ascii
    condition:
        filesize < 12MB and
        ($banner or $gen_user or $gen_pass or ($pool and $xmrig))
}

rule XMRig_V25_Config_Xor_And_Ua
{
    meta:
        author = "Jarmi"
        description = "V25 XMRig covert-config artifacts: XOR key chain, Java/Agent Stratum User-Agent, and /tmp/.lock mutex path"
        date = "2026-07-31"
        reference = "https://www.group-ib.com/blog/xmrig-covert-linux-pam-abuse/"
        confidence = "medium"
        family = "XMRig-V25-GEN-26"
    strings:
        $xor1 = "I3F0" ascii
        $xor2 = "CLIENT" ascii
        $ua   = "Java/Agent" ascii
        $lock = "/tmp/.lock" ascii
        $lan  = "-lan" ascii
    condition:
        filesize < 12MB and
        (($xor1 and $xor2) or ($ua and $lock) or ($lock and $lan))
}
