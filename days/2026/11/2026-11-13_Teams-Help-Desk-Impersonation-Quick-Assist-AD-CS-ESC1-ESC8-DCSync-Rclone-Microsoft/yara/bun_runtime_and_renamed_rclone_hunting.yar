/*
   Help desk impersonation to AD CS abuse (Microsoft Security Research, 2026-10-30) - generic hunting rules
   for the two tools named in the intrusion: a portable / renamed Bun runtime and a renamed Rclone binary
   Author: Jarmi
   Date: 2026-11-13
   Reference: https://www.microsoft.com/en-us/security/blog/2026/10/30/help-desk-impersonation-ad-cs-abuse-investigating-esc1-esc8-intrusion-paths/
   Honesty: Microsoft published NO sample, strings, file names or hashes for the Bun runtime or the Rclone
   binary (the only published hashes are three initial-access scripts - see iocs.csv - and they are not
   matched here because their content was not published). Both rules are GENERIC hunting rules built from
   my general knowledge of the tools, not from this case: rule 1 looks for Bun runtime / Bun single-file
   executable markers in a PE, rule 2 looks for Rclone Go-module and SFTP backend strings in a PE so that
   renamed copies (Microsoft reports SearchApp.exe) can be found by content rather than name. The exact
   byte strings were not verified against a sample in this case. Confidence low; use them for retro-hunts
   and triage of user-profile and file-server paths, not as blocking signatures. Not compiled (yara /
   yara-python not available in the authoring environment).
*/

rule Hunting_Bun_Runtime_PE_Outside_Standard_Name
{
    meta:
        author = "Jarmi"
        description = "Windows PE carrying Bun JavaScript runtime markers (Bun site URL, Bun single-file executable trailer or embedded virtual file system prefix). Hunt for copies under user profiles, KB-prefixed staging folders or with a name other than bun.exe"
        date = "2026-11-13"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/10/30/help-desk-impersonation-ad-cs-abuse-investigating-esc1-esc8-intrusion-paths/"
        confidence = "low"
        family = "Generic-Bun-Runtime"
    strings:
        $site = "https://bun.sh" ascii
        $trailer = "---- Bun! ----" ascii
        $bunfs = "~BUN" ascii
        $prod_wide = "Bun" wide fullword
        $orig_wide = "bun.exe" wide
    condition:
        uint16(0) == 0x5A4D and
        filesize < 200MB and
        ($trailer or $bunfs or ($site and ($prod_wide or $orig_wide)))
}

rule Hunting_Rclone_PE_SFTP_Backend_Possibly_Renamed
{
    meta:
        author = "Jarmi"
        description = "Windows PE containing the Rclone Go module path and SFTP backend / transfer option strings. Matches legitimate rclone.exe too; the value is finding Rclone under another name (Microsoft reports a renamed Rclone as SearchApp.exe on a file server)"
        date = "2026-11-13"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/10/30/help-desk-impersonation-ad-cs-abuse-investigating-esc1-esc8-intrusion-paths/"
        confidence = "low"
        family = "Generic-Rclone"
    strings:
        $mod = "github.com/rclone/rclone" ascii
        $sftp_backend = "rclone/backend/sftp" ascii
        $opt_transfers = "transfers" ascii fullword
        $opt_maxage = "max-age" ascii
    condition:
        uint16(0) == 0x5A4D and
        filesize < 150MB and
        $mod and
        ($sftp_backend or $opt_transfers or $opt_maxage)
}
