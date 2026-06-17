/*
   Fake event-invitation phishing kit - credential + OTP harvesting and RMM delivery
   Author: Jarmi  -  2026-06-17
   NOTE: These are HEURISTICS for saved kit pages / HTML+JS captured from a lure host, not
   signatures of a recovered binary. They key on the kit's fixed backend endpoints and the
   static brand-icon path. The PNG icons themselves have stable SHA-256s (see iocs.csv); these
   rules match the *page* that references the kit's endpoints and icons.
   References:
     https://any.run/cybersecurity-blog/us-fake-invitation-phishing/
     https://gbhackers.com/fake-invitation-phishing-campaign/
*/

rule FakeInvitation_PhishKit_NonGoogle_Flow
{
    meta:
        author      = "Jarmi"
        description = "Heuristic: saved fake-invitation kit page (non-Google flow) referencing processmail.php/process.php credential+OTP endpoints"
        date        = "2026-06-17"
        reference   = "https://any.run/cybersecurity-blog/us-fake-invitation-phishing/"
        confidence  = "high"
        family      = "fake-invitation-phishkit"
    strings:
        $e1 = "processmail.php" ascii nocase
        $e2 = "process.php" ascii nocase
        $e3 = "blocked.html" ascii nocase
        $e4 = "Incorrect Password" ascii nocase
    condition:
        filesize < 300KB and 2 of ($e*)
}

rule FakeInvitation_PhishKit_Google_Flow
{
    meta:
        author      = "Jarmi"
        description = "Heuristic: saved fake-invitation kit page (Google flow) referencing pass.php/mlog.php and the Telegram-relay endpoint"
        date        = "2026-06-17"
        reference   = "https://any.run/cybersecurity-blog/us-fake-invitation-phishing/"
        confidence  = "high"
        family      = "fake-invitation-phishkit"
    strings:
        $g1 = "pass.php" ascii nocase
        $g2 = "mlog.php" ascii nocase
        $g3 = "check_telegram_updates.php" ascii nocase
    condition:
        filesize < 300KB and 2 of ($g*)
}

rule FakeInvitation_PhishKit_IconSet
{
    meta:
        author      = "Jarmi"
        description = "Heuristic: fake-invitation kit page referencing the fixed /Image/ brand-icon set (office360/yahoo/aol/google/email)"
        date        = "2026-06-17"
        reference   = "https://gbhackers.com/fake-invitation-phishing-campaign/"
        confidence  = "medium"
        family      = "fake-invitation-phishkit"
    strings:
        $dir = "/Image/" ascii nocase
        $i1 = "office360.png" ascii nocase
        $i2 = "yahoo.png" ascii nocase
        $i3 = "aol.png" ascii nocase
        $i4 = "email.png" ascii nocase
    condition:
        filesize < 300KB and $dir and 2 of ($i*)
}
