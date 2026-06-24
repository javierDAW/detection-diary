/*
  YARA Rule: SRG / Luna Moth - Extortion Email Template Patterns
  Author: Jarmi
  Date: 2026-06-24
  Description: Detects SRG extortion email artifacts in .eml or .msg files or raw mail spool.
               SRG extortion emails follow a consistent template: they reference the victim
               organization's name, state that data has been exfiltrated, provide a payment
               deadline, and link to business-data-leaks[.]com. The durable anchors are the
               combination of the leak site domain, payment urgency language, and attorney-client
               privilege / data posting threat.
  Reference: https://www.ic3.gov/CSA/2026/260526.pdf
  Confidence: medium — template-based detection; FP possible if leak domain is mentioned
              in threat intelligence reports stored as .eml
  Note: HEURISTIC — no public sample hash. Template derived from public FBI/media descriptions.
  Family: SilentRansomGroup
*/

rule SRG_LunaMoth_Extortion_Email
{
    meta:
        author = "Jarmi"
        description = "SRG / Luna Moth extortion email template: leak domain + payment deadline language"
        date = "2026-06-24"
        reference = "https://www.ic3.gov/CSA/2026/260526.pdf"
        confidence = "medium"
        family = "SilentRansomGroup"

    strings:
        $leak_domain1 = "business-data-leaks.com" ascii wide nocase
        $leak_domain2 = "business-data-leaks[.]com" ascii wide nocase
        $pay_lang1    = "publish your data" ascii wide nocase
        $pay_lang2    = "your files have been exfiltrated" ascii wide nocase
        $pay_lang3    = "attorney-client privilege" ascii wide nocase
        $pay_lang4    = "notify your clients" ascii wide nocase
        $pay_lang5    = "publicly release" ascii wide nocase

    condition:
        filesize < 2MB
        and ($leak_domain1 or $leak_domain2)
        and 1 of ($pay_lang*)
}
