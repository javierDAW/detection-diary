rule Kali365_DeviceCode_Phishing_Kit_HTML
{
    // Heuristic content signature for the Kali365 (K365) device-code phishing
    // page template observed across the 126-host cluster. This matches retrieved
    // HTML / phishing-page captures, NOT a compiled binary sample. Anchors are the
    // loader string, the C2 polling host, the sibling-fetch Worker pattern and the
    // legitimate Microsoft device-auth endpoint opened in a popup.
    meta:
        author = "Jarmi"
        description = "Kali365 OAuth device-code phishing page template (HTML capture heuristic)"
        date = "2026-06-10"
        reference = "https://arcticwolf.com/resources/blog/kali365-expands-into-aws-microsoft-okta-xerox-max-messenger/"
        confidence = "medium"
        family = "Kali365"
    strings:
        $loader   = "Preparing your secure document" ascii nocase
        $c2       = "securehubcloud.com" ascii nocase
        $title    = "K365 Control" ascii nocase
        $devauth  = "oauth2/deviceauth" ascii nocase
        $devlogin = "microsoft.com/devicelogin" ascii nocase
        $worker   = ".workers.dev" ascii nocase
        $write    = "document.write" ascii nocase
    condition:
        filesize < 512KB and
        (
            $loader or $c2 or $title or
            ($devauth and $worker) or
            ($devlogin and $write)
        )
}
