rule DynoWiper_Sandworm_C0063_Heuristic
{
    meta:
        author       = "Jarmi"
        description  = "Heuristic for DynoWiper (C0063 Poland Wiper Attacks, dec-2025) — PDB + skiplist + 16-byte MT19937 wipe + ExitWindowsEx"
        date         = "2026-05-04"
        reference    = "https://www.welivesecurity.com/en/eset-research/dynowiper-update-technical-analysis-attribution/"
        reference2   = "https://attack.mitre.org/campaigns/C0063/"
        eset_family  = "Win32/KillFiles.NMO"
        confidence   = "medium-high (heuristic, no IOC hash)"
        family       = "DynoWiper"

    strings:
        $pdb       = "vagrant\\Documents\\Visual Studio 2013\\Projects\\Source\\Release\\Source.pdb" ascii
        $skip1     = "System32" wide ascii
        $skip2     = "Program Files" wide ascii
        $skip3     = "\\Windows\\" wide ascii
        // import names typical of DynoWiper logic
        $api1      = "GetLogicalDrives" ascii
        $api2      = "ExitWindowsEx" ascii
        $api3      = "SetFileAttributesW" ascii
        $api4      = "AdjustTokenPrivileges" ascii
        $api5      = "FindFirstFileW" ascii
        // Mersenne Twister mt19937 constants used in libstdc++/MSVC implementations
        $mt_const1 = { 6C DF 26 9D }   // 0x9D26DF6C — common mt19937 mask
        $mt_const2 = { EF C6 0B 9D }   // appears in MT word-tempering
        // Skiplist concatenation pattern
        $skiplist  = /(System32|Program Files|Program Files \(x86\)|Windows)\x00/ ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 600KB and
        (
          ($pdb)
          or
          (3 of ($api*) and 2 of ($skip*) and any of ($mt_const*))
        )
}
