/*
   O-UNC-066 / Pink Entra passkey-enrollment phishing kit
   Author: Jarmi  -  2026-07-15
   These rules match SAVED ARTEFACTS of the kit (captured HTML/PHP/JS from the phishing
   host, a threat-intel detonation, or an incident-response pull), NOT a confirmed malware
   binary. Okta reconstructed the kit flow from extracted code; the durable structure is the
   fixed stage-path set, the /backend.php panel POST, the ~1-second heartbeat poll, and the
   fake BIP-39 "recovery key" passkey pages. Tune before production; kit source rotates.
*/

rule Pink_Passkey_Kit_Stage_Paths
{
    meta:
        author = "Jarmi"
        description = "O-UNC-066/Pink phishing-kit page markup referencing the fixed operator-driven stage paths"
        date = "2026-07-15"
        reference = "https://www.okta.com/blog/threat-intelligence/vishing-actors-target-microsoft-entra-passkey-enrollment-/"
        confidence = "medium"
        family = "Pink-PasskeyKit"
    strings:
        $p1 = "/approve-authenticator" ascii
        $p2 = "/submit-authenticator" ascii
        $p3 = "/passkey/register" ascii
        $p4 = "/passkey/check" ascii
        $p5 = "/backend.php" ascii
        $p6 = "/submit-otp" ascii
    condition:
        filesize < 512KB and 3 of ($p1, $p2, $p3, $p4, $p5, $p6)
}

rule Pink_Passkey_Kit_Heartbeat_Panel
{
    meta:
        author = "Jarmi"
        description = "O-UNC-066/Pink kit client-side heartbeat polling of the operator panel plus backend POST of captured secrets"
        date = "2026-07-15"
        reference = "https://www.okta.com/blog/threat-intelligence/vishing-actors-target-microsoft-entra-passkey-enrollment-/"
        confidence = "medium"
        family = "Pink-PasskeyKit"
    strings:
        $panel = "backend.php" ascii
        $poll1 = "setInterval" ascii
        $poll2 = "1000" ascii
        $steer = "processing" ascii
        $post = "POST" ascii
    condition:
        filesize < 512KB and $panel and ($poll1 and $poll2) and ($steer or $post)
}

rule Pink_Passkey_Kit_Fake_Recovery_Phrase
{
    meta:
        author = "Jarmi"
        description = "O-UNC-066/Pink fake passkey 'recovery key' page presenting a BIP-39 seed phrase (no legitimate role in Entra passkey enrolment)"
        date = "2026-07-15"
        reference = "https://www.okta.com/blog/threat-intelligence/vishing-actors-target-microsoft-entra-passkey-enrollment-/"
        confidence = "low"
        family = "Pink-PasskeyKit"
    strings:
        $r1 = "recovery key" ascii nocase
        $r2 = "passkey" ascii nocase
        $r3 = "abandon" ascii
        $r4 = "ability" ascii
        $r5 = "able" ascii
    condition:
        filesize < 512KB and $r1 and $r2 and (2 of ($r3, $r4, $r5))
}
