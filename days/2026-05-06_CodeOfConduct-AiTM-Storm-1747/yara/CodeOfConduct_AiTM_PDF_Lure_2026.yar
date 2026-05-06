/*
   Author:      Jarmi
   Date:        2026-05-06
   Family:      Tycoon2FA-Lure (PDF social-engineering vehicle)
   Reference:   https://www.microsoft.com/en-us/security/blog/2026/05/04/breaking-the-code-multi-stage-code-of-conduct-phishing-campaign-leads-to-aitm-token-compromise/
*/

rule CodeOfConduct_AiTM_PDF_Lure_2026
{
    meta:
        author      = "Jarmi"
        description = "Heuristica para PDFs lure de la campana Code-of-Conduct AiTM (Storm-1747/Tycoon2FA, abr-2026): texto tematico + URI Action + dominios attacker conocidos o patron de palabras."
        date        = "2026-05-06"
        reference   = "https://www.microsoft.com/en-us/security/blog/2026/05/04/breaking-the-code-multi-stage-code-of-conduct-phishing-campaign-leads-to-aitm-token-compromise/"
        family      = "Tycoon2FA-Lure"
        confidence  = "medium (heuristic; not a per-sample SHA pin)"

    strings:
        $pdf_magic    = "%PDF-"
        $uri_action   = "/URI" ascii
        $tag_a        = "/A " ascii

        // Tema lure
        $t1           = "Code of Conduct" nocase
        $t2           = "Disciplinary Action" nocase
        $t3           = "Awareness Case Log" nocase
        $t4           = "Employee Device Handling" nocase
        $t5           = "Review Case Materials" nocase

        // Dominios attacker observados
        $d1           = "acceptable-use-policy-calendly" nocase
        $d2           = "compliance-protectionoutlook" nocase

        // Patron keyword + TLD barato
        $tld_de       = ".de/" nocase
        $tld_space    = ".space/" nocase
        $tld_email    = ".email/" nocase
        $tld_calendar = ".calendar/" nocase

    condition:
        $pdf_magic at 0
        and filesize < 4MB
        and $uri_action
        and $tag_a
        and (
              2 of ($t*)
              or any of ($d*)
              or (1 of ($t*) and 1 of ($tld_*))
            )
}
