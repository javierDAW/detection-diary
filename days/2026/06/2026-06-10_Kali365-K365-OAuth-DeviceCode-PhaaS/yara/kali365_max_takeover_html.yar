rule Kali365_MAX_Messenger_Takeover_HTML
{
    // Heuristic content signature for the Kali365 operator's MAX Messenger
    // account-takeover "prize claim" page (greatness-marketing[.]top). Matches the
    // hardcoded Telegram exfiltration config and the Russian-language prize/OTP
    // social-engineering strings. This matches retrieved HTML, not a binary.
    meta:
        author = "Jarmi"
        description = "Kali365 MAX Messenger takeover prize-claim phishing page (HTML capture heuristic)"
        date = "2026-06-10"
        reference = "https://arcticwolf.com/resources/blog/kali365-expands-into-aws-microsoft-okta-xerox-max-messenger/"
        confidence = "medium"
        family = "Kali365"
    strings:
        $tg_cfg   = "TELEGRAM_NOTIFY_CONFIG" ascii
        $tg_tok   = "8535071077:AAFus1ccm-puZ2htZkpKP_UyZfp3FTHFCzg" ascii
        $tg_chat  = "-5035652280" ascii
        $pixel    = "tk.mowell.tech" ascii nocase
        $ru_prize = "\xd0\x9f\xd0\xbe\xd0\xb4\xd1\x82\xd0\xb2\xd0\xb5\xd1\x80\xd0\xb6\xd0\xb4\xd0\xb5\xd0\xbd\xd0\xb8\xd0\xb5 \xd0\xb2\xd1\x8b\xd0\xb8\xd0\xb3\xd1\x80\xd1\x8b\xd1\x88\xd0\xb0" ascii
        $botname  = "sova_novosibirsk_bot" ascii nocase
    condition:
        filesize < 512KB and
        (
            $tg_tok or $tg_chat or $botname or
            ($tg_cfg and $pixel) or
            ($ru_prize and $tg_cfg)
        )
}
