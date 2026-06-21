/*
 * YARA rule: Icarus extortion note pattern
 * Author: Jarmi
 * Date: 2026-06-21
 * Reference: https://www.huntress.com/blog/klue-breach-investigation
 *            https://www.bleepingcomputer.com/news/security/klue-oauth-breach-linked-to-icarus-salesforce-data-theft-attacks/
 * Confidence: medium — heuristic; matches on keyword clusters from observed extortion emails
 * Family: Icarus
 * Description: Matches extortion emails and notes associated with the Icarus group
 *              (June 2026 Klue/Salesforce campaign). Looks for the combination of
 *              Session Messenger invitation, the "mr bean" alias, and extortion deadline language
 *              observed in the extortion emails sent to Huntress and other victims.
 *              CAUTION: Individual strings are common; alert only on multi-string matches.
 */

rule Icarus_Extortion_Note_June2026 {
    meta:
        author = "Jarmi"
        description = "Icarus extortion note — Session Messenger invitation + deadline + alias cluster"
        date = "2026-06-21"
        reference = "https://www.huntress.com/blog/klue-breach-investigation"
        confidence = "medium"
        family = "Icarus"

    strings:
        $session_invite = "write to us on Session" nocase
        $alias_mrbean = "mr bean" nocase
        $alias_mrbean2 = "mr.bean" nocase
        $deadline_48h = "48 hours" nocase
        $right_decision = "right decision" nocase
        $top_secret = "top secret" nocase
        $big_corps = "big corps" nocase
        $salesforce_ref = "Salesforce" nocase
        $klue_ref = "Klue" nocase
        $get_ready = "Get Ready" nocase

    condition:
        filesize < 1MB
        and (
            ($session_invite and $deadline_48h)
            or ($alias_mrbean and ($deadline_48h or $right_decision))
            or ($alias_mrbean2 and ($deadline_48h or $right_decision))
            or ($big_corps and $get_ready and $salesforce_ref)
            or ($session_invite and $klue_ref and $deadline_48h)
            or ($top_secret and $session_invite and ($salesforce_ref or $klue_ref))
        )
}
