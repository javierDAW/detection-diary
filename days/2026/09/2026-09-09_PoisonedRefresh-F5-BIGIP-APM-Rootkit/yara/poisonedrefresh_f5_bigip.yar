/*
  PoisonedRefresh (Sophos: Linux/Agnt-IC; F5 activity c05d5254) - F5 BIG-IP APM rootkit
  Author: Jarmi
  Date: 2026-09-09
  Reference: https://www.sophos.com/en-us/blog/dissecting-a-php-web-server-rootkit

  Scope and honesty note
  - Sophos published ONE sample hash and the key material below; no byte sequences or YARA rules were published.
  - Operational strings in the implant are RC4-encrypted, so strings such as the socket path are NOT expected in clear in the file.
    The RC4 key itself has to be available to the decryptor; whether it appears verbatim in the ELF has not been confirmed publicly.
  - Rule 1 is therefore medium confidence for files; rules 2 and 3 are intended for MEMORY images of an Apache worker or for
    carved PHP buffers, where the decrypted strings and the patched-in web shell constants exist.
  - The infected /usr/sbin/httpd carries the implant as a 0x5430-byte prefix; compare it with a known-good copy of the same
    release instead of relying on a signature.
*/

rule PoisonedRefresh_F5_RC4_Key_ELF
{
    meta:
        author = "Jarmi"
        description = "ELF file embedding the RC4 key Sophos documents for PoisonedRefresh string obfuscation"
        date = "2026-09-09"
        reference = "https://www.sophos.com/en-us/blog/dissecting-a-php-web-server-rootkit"
        confidence = "medium"
        family = "PoisonedRefresh"
    strings:
        $rc4_key = "TrswBWIl90Z5e38n" ascii
        $s_libc = "__libc_start_main" ascii
        $s_apr = "apr_dso_load" ascii
    condition:
        uint32(0) == 0x464c457f and filesize < 8MB and $rc4_key and ($s_libc or $s_apr)
}

rule PoisonedRefresh_F5_WebShell_Constants_Memory
{
    meta:
        author = "Jarmi"
        description = "Memory image or buffer holding the PoisonedRefresh web shell request prefix and cipher key"
        date = "2026-09-09"
        reference = "https://www.sophos.com/en-us/blog/dissecting-a-php-web-server-rootkit"
        confidence = "medium"
        family = "PoisonedRefresh"
    strings:
        $prefix = "BSOHAzPB" ascii
        $key = "wSLjN1beuR" ascii
        $input = "php://input" ascii
    condition:
        filesize < 2GB and $prefix and $key and $input
}

rule PoisonedRefresh_F5_Socket_And_Targets_Memory
{
    meta:
        author = "Jarmi"
        description = "Memory image holding the implant's decrypted socket path or token together with the targeted webtop script names"
        date = "2026-09-09"
        reference = "https://www.sophos.com/en-us/blog/dissecting-a-php-web-server-rootkit"
        confidence = "low"
        family = "PoisonedRefresh"
    strings:
        $sock = "/run/bigtlog.pipe" ascii
        $token = "Kzwd6jM5" ascii
        $t1 = "apm_css.php3" ascii
        $t2 = "full_wt.php3" ascii
        $t3 = "webtop_popup_css.php3" ascii
    condition:
        filesize < 2GB and ($sock or $token) and ($t1 or $t2 or $t3)
}
