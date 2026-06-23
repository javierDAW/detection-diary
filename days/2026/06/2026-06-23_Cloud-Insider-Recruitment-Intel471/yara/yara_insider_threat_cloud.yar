/*
 * YARA rules — Cloud Insider Threat / Infostealer Credential Harvest
 * Author: Jarmi
 * Date: 2026-06-23
 * Reference: https://www.helpnetsecurity.com/2026/06/11/report-cloud-insider-threats/
 *            https://www.trendmicro.com/en_us/research/25/j/how-vidar-stealer-2-upgrades-infostealer-capabilities.html
 * Confidence: HEURISTIC — these rules target behavioural patterns and string clusters
 *             common to Vidar-class stealers. They are not derived from a specific
 *             public sample with a verified hash. Tune aggressively in your environment
 *             before promoting to production block mode.
 * Family: Vidar-class infostealer / cloud credential harvester
 */

rule VidarClass_Telegram_C2_Resolve {
    meta:
        author = "Jarmi"
        description = "Heuristic: detects PE binaries that resolve Telegram API domains for C2 channel description lookup — common Vidar v2.0 and Stealc-class technique (Intel 471 May-2026 top stealers: Vidar #1, Stealc_v2 #2)"
        date = "2026-06-23"
        reference = "https://www.trendmicro.com/en_us/research/25/j/how-vidar-stealer-2-upgrades-infostealer-capabilities.html"
        confidence = "medium"
        family = "Vidar-class"

    strings:
        $s1 = "api.telegram.org" ascii wide
        $s3 = "getUpdates" ascii wide
        $s4 = "sendDocument" ascii wide
        $s5 = ".zip" ascii wide
        $cred1 = "Passwords" ascii wide
        $cred2 = "Cookies" ascii wide
        $cred3 = "Autofill" ascii wide
        $cred4 = "wallet.dat" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        $s1 and
        ($s3 or $s4) and
        2 of ($cred1, $cred2, $cred3, $cred4) and
        $s5
}

rule AiTM_PhishKit_Okta_Google_Token_Harvest {
    meta:
        author = "Jarmi"
        description = "Heuristic: detects PHP-based AiTM phishing kit pages targeting Okta and Google Workspace that route captured tokens to Telegram — matches pattern of 'Advanced Phishing Kit Targeting Okta and Google Workspace' advertised in underground markets Sept 2025 per Intel 471"
        date = "2026-06-23"
        reference = "https://www.helpnetsecurity.com/2026/06/11/report-cloud-insider-threats/"
        confidence = "medium"
        family = "AiTM-phishkit-okta-google"

    strings:
        $p1 = "okta" nocase ascii
        $p2 = "workspace.google" nocase ascii
        $p3 = "accounts.google" nocase ascii
        $tok1 = "session_token" nocase ascii
        $tok2 = "access_token" nocase ascii
        $tok3 = "id_token" nocase ascii
        $relay = "api.telegram.org/bot" ascii
        $curl1 = "curl_init" ascii
        $curl2 = "file_get_contents" ascii

    condition:
        filesize < 500KB and
        (
            ($p1 or $p2 or $p3) and
            (1 of ($tok1, $tok2, $tok3)) and
            $relay and
            (1 of ($curl1, $curl2))
        )
}

rule CloudInsider_Stealer_Log_Archive_Pattern {
    meta:
        author = "Jarmi"
        description = "Heuristic: detects ZIP archives with path structure matching credential-harvest logs assembled by Vidar/Stealc-class stealers — directories named after browsers and credential stores bundled with a system-info text file"
        date = "2026-06-23"
        reference = "https://www.helpnetsecurity.com/2026/06/11/report-cloud-insider-threats/"
        confidence = "medium"
        family = "stealer-log-archive"

    strings:
        $dir1 = "\\Passwords\\" ascii wide
        $dir2 = "\\Cookies\\" ascii wide
        $dir3 = "\\Autofill\\" ascii wide
        $dir4 = "\\Google\\Chrome\\" ascii wide
        $dir5 = "\\Microsoft\\Edge\\" ascii wide
        $sysinfo = "System_Info" ascii wide
        $sysinfo2 = "sysinfo.txt" ascii wide
        $wallet = "wallet.dat" ascii wide
        $screenshot = "screenshot.jpg" ascii wide

    condition:
        filesize < 50MB and
        3 of ($dir1, $dir2, $dir3, $dir4, $dir5) and
        (1 of ($sysinfo, $sysinfo2)) and
        (1 of ($wallet, $screenshot))
}
