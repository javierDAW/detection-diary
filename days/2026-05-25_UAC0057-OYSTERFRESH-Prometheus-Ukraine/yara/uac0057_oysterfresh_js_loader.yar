/*
   Title:        UAC-0057 Ghostwriter OYSTERFRESH JavaScript loader
   Author:       Jarmi
   Date:         2026-05-25
   Reference:    https://cert.gov.ua/article/6315762
   Reference:    https://thehackernews.com/2026/05/ghostwriter-targets-ukraine-government.html
   Reference:    https://socprime.com/active-threats/uac-0057-updates-its-toolkit-with-oysterfresh-oystershuck-and-oysterblues/
   Description:  Detects OYSTERFRESH-class JavaScript loader files associated with
                 the UAC-0057 / Ghostwriter Prometheus phishing campaign (CERT-UA
                 advisory #6315762, 22-May-2026). Anchors on the stacked decode
                 chain CERT-UA documents (string reversal + ROT13 + URL-decoding)
                 and on the persistence and C2 artefacts the JavaScript writes
                 (HKCU Run-key values MicrosoftEdgeUpdate / EdgeApp, scheduled
                 task MicrosoftEdgeUpdateTaskMachine, .icu Cloudflare-fronted
                 C2 domains, WScript.Shell and registry-write COM objects). The
                 rule requires the structural decode-chain anchor plus at least
                 two of the persistence or C2 anchors to balance recall against
                 false positives on benign obfuscated JavaScript.
   Confidence:   high
   Family:       oysterfresh
*/

rule uac0057_oysterfresh_js_loader_2026 : uac0057 ghostwriter oysterfresh
{
    meta:
        author = "Jarmi"
        date = "2026-05-25"
        description = "OYSTERFRESH JS loader — UAC-0057 / Ghostwriter Prometheus campaign (CERT-UA#6315762)"
        reference = "https://cert.gov.ua/article/6315762"
        confidence = "high"
        family = "oysterfresh"
        version = "1"

    strings:
        // structural decode chain anchors — required
        $reverse1   = "split('').reverse().join('')" ascii nocase
        $reverse2   = ".reverse().join(" ascii nocase
        $rot13a     = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" ascii
        $rot13b     = "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm" ascii
        $rot13c     = "charCodeAt" ascii nocase
        $urldec1    = "decodeURIComponent" ascii nocase
        $urldec2    = "unescape(" ascii nocase

        // persistence anchors
        $reg1       = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii nocase
        $reg2       = "MicrosoftEdgeUpdate" ascii nocase
        $reg3       = "EdgeApp" ascii nocase
        $task1      = "MicrosoftEdgeUpdateTaskMachine" ascii nocase
        $task2      = "schtasks /Create" ascii nocase

        // execution / COM anchors
        $com1       = "WScript.Shell" ascii nocase
        $com2       = "ActiveXObject" ascii nocase
        $com3       = "WScript.Network" ascii nocase
        $reg4       = "RegWrite" ascii nocase

        // C2 anchors
        $icu1       = ".icu" ascii nocase
        $icu2       = "POST" ascii nocase
        $xhr1       = "XMLHTTP" ascii nocase
        $xhr2       = "fetch(" ascii nocase

        // optional discovery anchors
        $disc1      = "COMPUTERNAME" ascii nocase
        $disc2      = "Win32_OperatingSystem" ascii nocase
        $disc3      = "LastBootUpTime" ascii nocase

    condition:
        filesize < 2MB
        and (any of ($reverse*)
             and any of ($rot13*)
             and any of ($urldec*))
        and (
              (2 of ($reg*) and 1 of ($task*))
           or (1 of ($com*) and 1 of ($icu*) and 1 of ($xhr*))
           or (2 of ($reg*) and 1 of ($com*) and 1 of ($icu*))
        )
        and 1 of ($disc*)
}
