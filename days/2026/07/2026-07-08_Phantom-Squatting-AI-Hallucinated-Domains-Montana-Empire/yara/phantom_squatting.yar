/*
   Phantom Squatting - Montana Empire phishing kit (AI-hallucinated domain infrastructure)
   Author: Jarmi
   Reference: https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/
   Note: The kit is a full brand clone of a national postal e-commerce marketplace, staged on a
   domain an LLM invented and an adversary registered first. These rules key on the kit's login
   branding, its PHP backend endpoints and a generic Telegram-exfil brand-clone heuristic. Branding
   strings are ASCII-normalized (the banner "Kimseye Guvenme" drops its diacritics).
*/

rule MontanaEmpire_PhishKit_Branding
{
    meta:
        author = "Jarmi"
        description = "Montana Empire phishing-kit login / branding strings (postal e-commerce brand clone)"
        date = "2026-07-08"
        reference = "https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/"
        confidence = "high"
        family = "MontanaEmpire"
    strings:
        $b1 = "ENTER THE EMPIRE" ascii wide
        $b2 = "Enter Access Key" ascii wide
        $b3 = "Kimseye Guvenme" ascii wide
        $b4 = "User Protocol" ascii wide
        $b5 = "Lost Access" ascii wide
        $b6 = "MONTANA" ascii wide
    condition:
        filesize < 20MB and
        (
            ($b1 or $b2) and
            ($b3 or $b4 or $b5 or $b6)
        )
}

rule MontanaEmpire_PhishKit_Backend
{
    meta:
        author = "Jarmi"
        description = "Montana Empire kit server-side PHP endpoints plus Telegram-based credential exfiltration"
        date = "2026-07-08"
        reference = "https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/"
        confidence = "high"
        family = "MontanaEmpire"
    strings:
        $p1 = "mentalite.php" ascii wide
        $p2 = "panel_track.php" ascii wide
        $p3 = "verify_api.php" ascii wide
        $t1 = "api.telegram.org/bot" ascii wide
        $t2 = "sendMessage" ascii wide
        $z1 = "letgovip.zip" ascii wide
    condition:
        filesize < 20MB and
        (
            ($p1 or $p2 or $p3 or $z1) and
            ($t1 or $t2)
        )
}

rule PhantomSquat_TelegramExfil_Kit_Heuristic
{
    meta:
        author = "Jarmi"
        description = "Heuristic for a Telegram-exfil brand-clone phishing kit - real-time scraper + card/IBAN/OTP capture + Telegram bot C2"
        date = "2026-07-08"
        reference = "https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/"
        confidence = "medium"
        family = "PhantomSquatKit"
    strings:
        $c1 = "api.telegram.org/bot" ascii wide
        $c2 = "chat_id" ascii wide
        $f1 = "cardNumber" ascii wide nocase
        $f2 = "iban" ascii wide nocase
        $f3 = "otp" ascii wide nocase
        $f4 = "cvv" ascii wide nocase
    condition:
        filesize < 20MB and
        (
            ($c1 and $c2) and
            ($f1 or $f2 or $f3 or $f4)
        )
}
