rule AWS_Console_AiTM_input24_Kit_JS_2026
{
    // Matches the JavaScript bundle of the input_24 AiTM phishing kit that
    // clones the AWS console sign-in page and relays MFA (Datadog, Jun 2026).
    meta:
        author = "Jarmi"
        description = "input_24 AiTM phishing kit JS: victim-gating + AWS console clone + MFA relay endpoints"
        date = "2026-07-01"
        reference = "https://securitylabs.datadoghq.com/articles/behind-the-console-aws-aitm-phishing-kit-and-beyond/"
        confidence = "high"
        family = "input_24-phishing-kit"
    strings:
        $gate1 = "input_24" ascii wide
        $gate2 = "/api/check" ascii wide
        $gate3 = "/api/me" ascii wide
        $api1  = "/api/login" ascii wide
        $api2  = "/api/auth" ascii wide
        $cookie = "validEmail" ascii wide
        $title = "Amazon Web Services Sign-In" ascii wide
        $isroot = "isRootUser" ascii wide
    condition:
        filesize < 3MB and
        (($gate1 and $gate2 and $gate3) or
         ($cookie and ($api1 or $api2)) or
         ($title and $isroot and ($gate1 or $cookie)))
}

rule AWS_AiTM_Validation_Batch_2026
{
    // Matches the attacker validation batch file uploaded to VirusTotal on
    // 2026-06-19: pings a decoy domain, curls the AWS phishing host, WHOIS.
    meta:
        author = "Jarmi"
        description = "Attacker validation .bat referencing the AWS console AiTM phishing infrastructure"
        date = "2026-07-01"
        reference = "https://securitylabs.datadoghq.com/articles/behind-the-console-aws-aitm-phishing-kit-and-beyond/"
        confidence = "medium"
        family = "input_24-phishing-kit"
    strings:
        $d1 = "aws.us-west-login.com" ascii wide nocase
        $d2 = "workspaceprotection-fuckgoogle" ascii wide nocase
        $c1 = "curl" ascii nocase
        $c2 = "whois" ascii nocase
        $c3 = "ping" ascii nocase
    condition:
        filesize < 64KB and
        ($d2 or ($d1 and ($c1 or $c2 or $c3)))
}

rule SendGrid_PoisonSeeds_SPA_2026
{
    // Matches the concurrent SendGrid-impersonation React SPA (PoisonSeeds
    // lineage) that shares registrar/window with the AWS kit.
    meta:
        author = "Jarmi"
        description = "PoisonSeeds-lineage SendGrid-impersonation SPA with 2fa route structure"
        date = "2026-07-01"
        reference = "https://blog.nviso.eu/2025/08/12/shedding-light-on-poisonseeds-phishing-kit/"
        confidence = "medium"
        family = "PoisonSeeds"
    strings:
        $r1 = "/2fa/email/" ascii wide
        $r2 = "/2fa/sms/" ascii wide
        $r3 = "/2fa/ga/" ascii wide
        $brand = "SendGrid" ascii wide nocase
        $twofid = "twoFactorId" ascii wide
    condition:
        filesize < 3MB and
        ($brand and $twofid and ($r1 or $r2 or $r3))
}
