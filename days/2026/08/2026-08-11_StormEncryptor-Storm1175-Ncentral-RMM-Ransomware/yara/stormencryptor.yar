rule StormEncryptor_Locker_Win64
{
    // Detects the StormEncryptor C++ Win64 locker used by Storm-1175 (former Medusa affiliate),
    // keyed on the two confirmed on-disk artifacts it embeds: the .encrypted extension it appends
    // and the ransom note filename it drops into every scanned directory. Low-fidelity by design
    // (only two public strings); use as a triage aid alongside the SHA-256 IOC, not as a sole
    // verdict. Bound tightly to a PE to reduce false positives on documents that mention the note.
    meta:
        author = "Jarmi"
        description = "StormEncryptor locker - .encrypted extension + !!!README_FIRST!!!.txt note (PE)"
        date = "2026-08-11"
        reference = "https://www.bleepingcomputer.com/news/security/new-stormencryptor-ransomware-used-by-former-medusa-affiliate/"
        confidence = "low"
        family = "StormEncryptor"
        sha256 = "c19ded65e822bb43ad0381c58abf33b7c8890f7bcc7125058a0c849c7e1a6054"
    strings:
        $ext = ".encrypted" ascii wide
        $note = "!!!README_FIRST!!!.txt" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and $ext and $note
}

rule StormEncryptor_ReadmeFirst_Artifact
{
    // Broad host-artifact heuristic (no MZ gate) that flags any file embedding both the
    // StormEncryptor ransom note filename and the .encrypted extension - e.g. the locker, a
    // packed stage, or a config blob. Higher recall, lower precision; pair with the note-pair
    // and Cloudflared/svchost-in-Documents host signals before escalating.
    meta:
        author = "Jarmi"
        description = "StormEncryptor artifact heuristic - note filename + encrypted extension in any file"
        date = "2026-08-11"
        reference = "https://thehackernews.com/2026/08/china-linked-hackers-deploy-new.html"
        confidence = "low"
        family = "StormEncryptor"
    strings:
        $note = "!!!README_FIRST!!!.txt" ascii wide
        $ext = ".encrypted" ascii wide
    condition:
        filesize < 15MB and ($note and $ext)
}
