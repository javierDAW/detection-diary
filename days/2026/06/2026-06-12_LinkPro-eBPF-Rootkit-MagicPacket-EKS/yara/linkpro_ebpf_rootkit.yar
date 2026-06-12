import "elf"

// LinkPro eBPF rootkit family (Synacktiv CSIRT, 2025-10).
// These rules are repo-authored adaptations anchored on durable module/string
// artifacts, not a copy of the vendor signature set. Confidence: high on the BPF
// modules and libld.so (unique strings), medium on the Go orchestrator (Go import
// paths can be mimicked). Reference hashes are the Synacktiv samples; LinkPro is
// rebuilt per intrusion so prefer the structural/behavioural anchors over hashes.

rule MAL_LinkPro_Go_Orchestrator_Linux
{
    meta:
        author = "Jarmi"
        description = "LinkPro Golang eBPF rootkit orchestrator (main module + embedded resources)"
        date = "2026-06-12"
        reference = "https://www.synacktiv.com/en/publications/linkpro-ebpf-rootkit-analysis"
        confidence = "medium"
        family = "LinkPro"
        hash = "1368f3a8a8254feea14af7dc928af6847cab8fcceec4f21e0166843a75e81964"
        hash = "d5b2202b7308b25bda8e106552dafb8b6e739ca62287ee33ec77abe4016e698b"
    strings:
        $mod        = "link-pro/link-client" ascii
        $res_libld  = "resources/libld.so" ascii
        $res_lkm    = "resources/arp_diag.ko" ascii
        $cfg_marker = "CFG0" ascii
        $hide_sym   = "hidePrograms" ascii
        $knock_sym  = "knock_prog" ascii
    condition:
        uint32(0) == 0x464c457f
        and filesize > 3MB and filesize < 60MB
        and ($mod or (($res_libld or $res_lkm) and ($hide_sym or $knock_sym or $cfg_marker)))
}

rule MAL_LinkPro_Hide_eBPF_Module
{
    meta:
        author = "Jarmi"
        description = "LinkPro Hide eBPF module (getdents/sys_bpf tracepoint hooks)"
        date = "2026-06-12"
        reference = "https://www.synacktiv.com/en/publications/linkpro-ebpf-rootkit-analysis"
        confidence = "high"
        family = "LinkPro"
        hash = "b8c8f9888a8764df73442ea78393fe12464e160d840c0e7e573f5d9ea226e164"
    strings:
        $tp_getdents   = "/syscalls/sys_enter_getdents" ascii
        $tp_bpf        = "/syscalls/sys_enter_bpf" ascii
        $dbg_hideid    = "HIDING NEXT_ID" ascii
        $dbg_bpfcmd    = "BPF cmd: %d, start_id" ascii
        $hidden_file   = ".tmp~data" ascii
    condition:
        uint32(0) == 0x464c457f
        and filesize < 2MB
        and (($tp_getdents or $tp_bpf) and ($dbg_hideid or $dbg_bpfcmd or $hidden_file))
}

rule MAL_LinkPro_Knock_eBPF_Module
{
    meta:
        author = "Jarmi"
        description = "LinkPro Knock eBPF module (XDP/TC magic-packet listener, window 54321)"
        date = "2026-06-12"
        reference = "https://www.synacktiv.com/en/publications/linkpro-ebpf-rootkit-analysis"
        confidence = "high"
        family = "LinkPro"
        hash = "364c680f0cab651bb119aa1cd82fefda9384853b1e8f467bcad91c9bdef097d3"
    strings:
        $xdp        = "xdp_ingress" ascii
        $tc         = "tc_egress" ascii
        $dbg_knock  = "[DBG-KNOCK]" ascii
        $dbg_tc     = "[TC] REWRITE_BACK" ascii
        $cn_knock   = "敲门包" ascii
    condition:
        uint32(0) == 0x464c457f
        and filesize < 2MB
        and (($xdp or $tc) and ($dbg_knock or $dbg_tc or $cn_knock))
}

rule MAL_LinkPro_LdPreload_libld
{
    meta:
        author = "Jarmi"
        description = "LinkPro libld.so userspace hiding library (libc hooks)"
        date = "2026-06-12"
        reference = "https://www.synacktiv.com/en/publications/linkpro-ebpf-rootkit-analysis"
        confidence = "high"
        family = "LinkPro"
        hash = "b11a1aa2809708101b0e2067bd40549fac4880522f7086eb15b71bfb322ff5e7"
    strings:
        $f_preload  = "ld.so.preload" ascii
        $f_procnet  = "/proc/net/tcp" ascii
        $f_hidden   = ".tmp~data" ascii
        $f_persist  = ".system" ascii
        $f_cron     = "sshids" ascii
        $sym_conceal = "toyincang" ascii
    condition:
        uint32(0) == 0x464c457f
        and filesize < 500KB
        and elf.type == elf.ET_DYN
        and ($f_hidden or $sym_conceal)
        and ($f_preload or $f_procnet or $f_persist or $f_cron)
}
