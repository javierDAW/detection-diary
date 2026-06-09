/*
   Kyber ransomware - ELF (Linux/ESXi) and PE (Windows) structural rules
   Author: Jarmi
   These rules combine stable string anchors from the analyzed March-2026 samples with
   structural markers (ELF/PE magic, encrypted-file trailer markers, native ESXi tooling).
   Kyber is rebuilt per campaign, so pair these with the behavioral Sigma/KQL content;
   the durable detection is the recovery-inhibition / esxcli-kill behavior, not the bytes.
   Reference: https://www.rapid7.com/blog/post/tr-kyber-ransomware-double-trouble-windows-esxi-attacks-explained/
*/

rule Kyber_ELF_ESXi_Encryptor
{
    meta:
        author      = "Jarmi"
        description = "Kyber Linux/ESXi ELF encryptor: native esxcli VM kill, /vmfs/volumes targeting, .xhsyw extension, and KYBER/CDTA/ATDC metadata trailer markers"
        date        = "2026-06-09"
        reference   = "https://www.rapid7.com/blog/post/tr-kyber-ransomware-double-trouble-windows-esxi-attacks-explained/"
        confidence  = "high"
        family      = "Kyber"
    strings:
        $esxcli   = "esxcli vm process" ascii
        $vmfs     = "/vmfs/volumes" ascii
        $ext      = ".xhsyw" ascii
        $bak      = ".cryptdata_backup" ascii
        $sig      = ".locksignal" ascii
        $motd     = "/usr/lib/vmware/hostd/docroot" ascii
        $m1       = "KYBER" ascii
        $m2       = "CDTA" ascii
        $m3       = "ATDC" ascii
    condition:
        uint32(0) == 0x464c457f and filesize < 30MB and
        ($ext or $bak or $sig) and
        ($esxcli or $vmfs or $motd) and
        ($m1 or $m2 or $m3)
}

rule Kyber_PE_Windows_Encryptor
{
    meta:
        author      = "Jarmi"
        description = "Kyber Windows Rust encryptor (win_encryptor 1.0): boomplay mutex, .#~~~ extension, READ_ME_NOW note, cargo build path, and the recovery-inhibition / Hyper-V stop command strings"
        date        = "2026-06-09"
        reference   = "https://www.rapid7.com/blog/post/tr-kyber-ransomware-double-trouble-windows-esxi-attacks-explained/"
        confidence  = "high"
        family      = "Kyber"
    strings:
        $proj   = "win_encryptor" ascii wide
        $mutex  = "boomplay.com/songs/182988982" ascii wide
        $note   = "READ_ME_NOW.txt" ascii wide
        $icon   = "fucked_icon" ascii wide
        $cargo  = "index.crates.io-6f17d22bba15001f" ascii
        $vm     = "Stop-VM" ascii wide
        $rec    = "recoveryenabled No" ascii wide
        $vss    = "Win32_ShadowCopy" ascii wide
    condition:
        uint16(0) == 0x5a4d and filesize < 30MB and
        ($proj or $mutex or $icon or $cargo) and
        ($note or $vm or $rec or $vss)
}
