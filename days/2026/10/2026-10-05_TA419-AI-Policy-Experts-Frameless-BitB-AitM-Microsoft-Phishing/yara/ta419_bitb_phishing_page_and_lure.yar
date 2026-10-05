/*
  Title: TA419 Frameless BitB phishing page and first-contact email (content rules)
  Author: Jarmi
  Date: 2026-10-05
  Reference: https://www.proofpoint.com/us/blog/threat-insight/hallucinating-credibility-china-aligned-ta419-impersonates-its-way-us-ai-policy
  Scope: these rules scan saved web-page captures (urlscan, sandbox or proxy-cache HTML and JavaScript) and exported .eml files.
  Source of the match strings: Proofpoint's description of the kit and the lures. No sample or capture was published or reviewed,
  so the strings have not been confirmed against real files. The script paths are generic and the OfficeHome client ID is a
  legitimate Microsoft value: the conditions require several markers together, and a hit is a lead for manual review.
*/

rule TA419_BitB_Phishing_Page_Kit_Markers
{
    meta:
        author = "Jarmi"
        description = "Saved phishing page or script that carries the Frameless BitB driver and telemetry paths reported for TA419, with the Microsoft OfficeHome client ID or a OneDrive share proxy marker"
        date = "2026-10-05"
        reference = "https://www.proofpoint.com/us/blog/threat-insight/hallucinating-credibility-china-aligned-ta419-impersonates-its-way-us-ai-policy"
        confidence = "low"
        family = "TA419 Frameless BitB AitM"
    strings:
        $p_secondary = "/secondary/script.js" ascii wide
        $p_primary = "/primary/script.js" ascii wide
        $p_observe = "/secondary/observe.js" ascii wide
        $client = "4765445b-32c6-49b0-83e6-1d93765276ca" ascii wide
        $oauth = "/common/oauth2/v2.0/authorize" ascii wide
        $share = "1drv.ms" ascii wide
        $turnstile = "challenges.cloudflare.com/turnstile" ascii wide
    condition:
        filesize < 3MB and
        (
            ($p_observe and $p_secondary) or
            ($p_observe and $p_primary) or
            ($p_secondary and $p_primary and ($client or $share)) or
            ($p_observe and $client and $oauth) or
            ($p_primary and $turnstile and $share)
        )
}

rule TA419_First_Contact_Email_Lure_Markers
{
    meta:
        author = "Jarmi"
        description = "Exported email (.eml) with a TA419 sender address or lure text from Proofpoint's report: Anthropic feedback subject, fictitious AI Policy Advisory Committee, or the Senate report request"
        date = "2026-10-05"
        reference = "https://www.proofpoint.com/us/blog/threat-insight/hallucinating-credibility-china-aligned-ta419-impersonates-its-way-us-ai-policy"
        confidence = "medium"
        family = "TA419 AI policy impersonation"
    strings:
        $a1 = "leparker@mail.com" ascii wide nocase
        $a2 = "hcrediker@mail.com" ascii wide nocase
        $a3 = "hcrediker@outlook.com" ascii wide nocase
        $d1 = "tw-koryu.org" ascii wide nocase
        $d2 = "heritiages.org" ascii wide nocase
        $d3 = "heritiage.org" ascii wide nocase
        $d4 = "shinjirou.info" ascii wide nocase
        $s1 = "Request for Feedback on Military Integration of Claude" ascii wide nocase
        $l1 = "AI Policy Advisory Committee" ascii wide nocase
        $l2 = "Senate Committee on Foreign Relations" ascii wide nocase
        $h1 = "From:" ascii
        $h2 = "Received:" ascii
    condition:
        filesize < 2MB and $h1 and $h2 and
        (
            $a1 or $a2 or $a3 or $d1 or $d2 or $d3 or $d4 or
            $s1 or
            ($l1 and $l2)
        )
}
