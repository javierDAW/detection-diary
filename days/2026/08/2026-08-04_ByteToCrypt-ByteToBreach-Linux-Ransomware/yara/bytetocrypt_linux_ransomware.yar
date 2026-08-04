// YARA rules for the ByteToCrypt Linux ransomware (ByteToBreach actor; TLPBLACK, 2026-07-28).
// The encryptor is a stripped ELF64, statically linked musl/OpenSSL. Strings target its fixed
// anti-forensics command block and developer messages; opcodes target the XOR/Base64 decoders.

rule ByteToCrypt_Linux_Ransomware_Strings
{
    meta:
        author = "Jarmi"
        description = "ByteToCrypt Linux ransomware: fixed anti-forensics commands, developer messages and .encrypted output marker"
        date = "2026-08-04"
        reference = "https://tlpblack.net/blog/20260728-a-deep-dive-into-bytetobreach-s-bytetocrypt-ransomware"
        confidence = "high"
        family = "ByteToCrypt"
        hash = "14ed580291658fa6410f4cbb18d9a2f979b93f4ce640c7445d999bcf440492e8"
    strings:
        $af_kill    = "killall -9 rsyslogd syslog-ng auditd systemd-journald 2>/dev/null" ascii
        $af_rm      = "rm -rf /var/log/* /var/log/journal/* /run/log/journal/* /etc/audit/* 2>/dev/null" ascii
        $note_yay   = "Note successfully Written, Yayy !" ascii
        $key_decode = "Decoded public key:" ascii
        $ext        = "%s.encrypted" ascii
        $self       = "bytetocrypt" ascii
    condition:
        filesize < 12MB and
        uint32(0) == 0x464C457F and
        ($af_kill or $af_rm or $note_yay or $key_decode or ($ext and $self))
}

rule ByteToCrypt_Linux_Ransomware_Decoders
{
    meta:
        author = "Jarmi"
        description = "ByteToCrypt config decoders: single-byte XOR loop and unrolled Base64 table lookup (stack offsets wildcarded)"
        date = "2026-08-04"
        reference = "https://tlpblack.net/blog/20260728-a-deep-dive-into-bytetobreach-s-bytetocrypt-ransomware"
        confidence = "medium"
        family = "ByteToCrypt"
    strings:
        $xor_decoder = {
            0F B6 00 8B 55 ?? 48 63 CA 48 8B 55 ?? 48 01 CA
            32 45 ?? 88 02 83 45 ?? 01 8B 45 ?? 3B 45 ?? 7C ??
        }
        $base64_decoder = {
            0F B6 00 0F B6 C0 48 98 0F B6 80 ?? ?? ?? ??
            0F B6 C0 C1 E0 12 89 45 ??
            8B 45 ?? 48 98 48 8D 50 01 48 8B 45 ?? 48 01 D0
            0F B6 00 0F B6 C0 48 98 0F B6 80 ?? ?? ?? ??
            0F B6 C0 C1 E0 0C 09 45 ??
        }
    condition:
        filesize < 12MB and
        uint32(0) == 0x464C457F and
        ($xor_decoder or $base64_decoder)
}
