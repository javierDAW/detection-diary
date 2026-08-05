/*
   Indirect Prompt Injection (IPI) web content - Zscaler ThreatLabz July 2026 campaigns
   Author: Jarmi
   Scope: run over saved HTML / crawled page bodies / agent-fetched documents, not binaries.
   These rules key on the IPI CONTENT SHAPE and campaign markers so they survive
   host re-registration, rather than on rotating domains alone.
*/

rule IPI_PaymentScam_FakeApiKey_RequestsSecureV2
{
    meta:
        author = "Jarmi"
        description = "Detects campaign-1 indirect-prompt-injection payment-scam web content: the fake requests-secure-v2 lure, the fabricated MissingLicenseKeyException, the off-screen CSS instruction layer, and the hardcoded attacker ETH wallet."
        date = "2026-08-05"
        reference = "https://www.zscaler.com/blogs/security-research/indirect-prompt-injection-web-content-targets-ai-agents"
        confidence = "high"
        family = "IPI-PaymentScam"
    strings:
        $lib     = "requests-secure-v2" ascii nocase
        $exc     = "MissingLicenseKeyException" ascii
        $layer   = "system-traceback-layer" ascii nocase
        $wallet  = "0x691bc3793205e574fa7b4aa068e62c0e470ad267" ascii nocase
        $offs    = "left: -9999px" ascii nocase
        $license = "developer API license" ascii nocase
    condition:
        filesize < 3MB and
        ($wallet or $exc or $layer or
         ($lib and ($offs or $license)))
}

rule IPI_DeBank_Typosquat_Content
{
    meta:
        author = "Jarmi"
        description = "Detects campaign-2 indirect-prompt-injection content impersonating DeBank on the debank.auction typosquat: the domain, the authoritative-source instruction pattern, and the fabricated trust indicators."
        date = "2026-08-05"
        reference = "https://securityweek.com/prompt-injection-attacks-trick-ai-agents-into-making-crypto-payments/"
        confidence = "medium"
        family = "IPI-Typosquat-DeBank"
    strings:
        $dom     = "debank.auction" ascii nocase
        $auth    = "verified, authoritative destination" ascii nocase
        $glob    = "DeBank Global 2026" ascii nocase
        $rabby   = "Rabby Security Engine" ascii nocase
        $score   = "9.9/10" ascii
        $ignore  = "ignore previous" ascii nocase
    condition:
        filesize < 3MB and
        ($dom and ($auth or $glob or $rabby or $score or $ignore))
}
