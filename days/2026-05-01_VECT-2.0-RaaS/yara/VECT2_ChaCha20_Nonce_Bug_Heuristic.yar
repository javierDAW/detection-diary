rule VECT2_ChaCha20_Nonce_Bug_Heuristic
{
    meta:
        author       = "Jarmi"
        description  = "Multi-platform PE+ELF heuristic for VECT 2.0 RaaS — marker path, EVTX-XOR key 0xBB55FF59DF597B8D, libsodium static symbol, .vect extension"
        date         = "2026-05-01"
        reference    = "https://research.checkpoint.com/"
        confidence   = "medium-high (heuristic — marker-anchored)"
        family       = "VECT"

    strings:
        // Killswitch / marker paths
        $marker_win   = "ProgramData\\.vect" ascii nocase
        $marker_lin   = "/var/run/.vect" ascii
        $ext          = ".vect" ascii nocase

        // EVTX clearing XOR key (8 bytes)
        $xor_key_le   = { 8D 7B 59 DF 59 FF 55 BB }
        $xor_key_be   = { BB 55 FF 59 DF 59 7B 8D }

        // libsodium static link symbols
        $libsodium1   = "crypto_stream_chacha20_ietf" ascii
        $libsodium2   = "crypto_stream_chacha20" ascii
        $libsodium3   = "sodium_init" ascii

        // Operational/CLI flags shipped in the encesxi.elf for SSH lateral
        $ssh_flag1    = "--ssh-keyfile" ascii
        $ssh_flag2    = "--ssh-userlist" ascii

        // Geofencing strings (CIS exclusion)
        $geo1         = "timedatectl" ascii
        $geo2         = "LC_ALL" ascii
        $geo3         = "LANG" ascii

    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and
        filesize < 6MB and
        (
          $xor_key_le or $xor_key_be or
          (
            (any of ($marker_win,$marker_lin)) and
            $ext and
            (any of ($libsodium*)) and
            (any of ($ssh_flag*) or any of ($geo*))
          )
        )
}
