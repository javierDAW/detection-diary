/*
  Title: Exported sign-in and inbox-rule evidence for the 2026 Microsoft 365 token replay campaign
  Author: Jarmi
  Date: 2026-10-28
  Reference: https://www.huntress.com/blog/token-replay-spray
  Scope: Huntress published no malware sample, so these rules match exported evidence (Entra sign-in log JSON or CSV, Exchange rule exports), not a binary. They were not run
  against real data and are triage aids for case folders and log exports. Network indicators age quickly; re-validate before treating a hit as current.
*/

rule M365_Token_Replay_Signin_Export_Campaign_Markers
{
    meta:
        author = "Jarmi"
        description = "Exported Entra sign-in data containing Office or Broker client IDs together with 1337 Services replay addresses or scripted request types"
        date = "2026-10-28"
        reference = "https://www.huntress.com/blog/token-replay-spray"
        confidence = "medium"
        family = "M365 token spray and replay (1337 Services)"
    strings:
        $app1 = "d3590ed6-52b3-4102-aeff-aad2292ab01c" ascii wide nocase
        $app2 = "29d9ed98-a469-4536-ade2-f981bc1d605e" ascii wide nocase
        $ip = "193.26.115." ascii wide
        $req1 = "OAuth2:Token" ascii wide
        $req2 = "Cmsi:Cmsi" ascii wide
    condition:
        filesize < 200MB and ($app1 or $app2) and $ip and ($req1 or $req2)
}

rule M365_Hiding_Inbox_Rule_Export_Payroll_Or_Hidden_Folder
{
    meta:
        author = "Jarmi"
        description = "Exported Exchange inbox-rule data that moves mail to RSS or Conversation History folders and matches payroll or bank keywords"
        date = "2026-10-28"
        reference = "https://www.huntress.com/blog/token-replay-spray"
        confidence = "low"
        family = "M365 BEC hiding rules"
    strings:
        $f1 = "RSS Feeds" ascii wide
        $f2 = "RSS Subscriptions" ascii wide
        $f3 = "Conversation History" ascii wide
        $k1 = "direct deposit" ascii wide nocase
        $k2 = "payroll" ascii wide nocase
        $k3 = "bonus" ascii wide nocase
        $mv = "MoveToFolder" ascii wide
    condition:
        filesize < 50MB and $mv and ($f1 or $f2 or $f3) and ($k1 or $k2 or $k3)
}
