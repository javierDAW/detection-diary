/*
  Title: AdFection - Candiru implant C2 strings and Controlium ad-tasking script strings
  Author: Jarmi
  Date: 2026-10-26
  Reference: https://citizenlab.ca/research/how-discover-tech-turned-targeted-ads-into-a-pipeline-for-spyware/
  Scope: rule 1 targets decrypted memory of the Candiru Windows implant, because the sample obfuscates its strings with a 48-byte repeating XOR key and the plain domains will
  not appear in the file on disk. Rule 2 targets Controlium ad-tasking script or HTML captured from a browser cache or proxy. No Controlium script sample or Candiru plaintext
  dump was published, so both rules match names and URLs from the report, were not run against a real sample, and are triage aids only.
*/

rule AdFection_Candiru_Implant_C2_Strings_Memory
{
    meta:
        author = "Jarmi"
        description = "Process memory or dump holding the Candiru Windows implant hardcoded C2 domains (after XOR decoding)"
        date = "2026-10-26"
        reference = "https://citizenlab.ca/research/how-discover-tech-turned-targeted-ads-into-a-pipeline-for-spyware/"
        confidence = "medium"
        family = "Candiru"
    strings:
        $c1 = "fearevolve.com" ascii wide nocase
        $c2 = "jobmarcher.com" ascii wide nocase
        $c3 = "insightenterprisells.com" ascii wide nocase
        $c4 = "plasticbells.com" ascii wide nocase
        $chk1 = "http://www.google.com" ascii wide
        $chk2 = "http://www.microsoft.com" ascii wide
    condition:
        filesize < 200MB and (($c1 or $c2 or $c3 or $c4) and ($chk1 or $chk2))
}

rule AdFection_Controlium_Ad_Tasking_Script_Strings
{
    meta:
        author = "Jarmi"
        description = "Script, HTML or cache file referencing Discover-Tech Controlium NOAS getAd tasking endpoints"
        date = "2026-10-26"
        reference = "https://citizenlab.ca/research/how-discover-tech-turned-targeted-ads-into-a-pipeline-for-spyware/"
        confidence = "low"
        family = "Controlium"
    strings:
        $n1 = "noas.mtrtb.com/getAd" ascii wide nocase
        $n2 = "noas.powerium.net/getAd" ascii wide nocase
        $n3 = "events.myweb3id.io/cplatform/getAd" ascii wide nocase
        $n4 = "infinoas.mtrtb.com" ascii wide nocase
        $n5 = "pqv2.mtrtb.com/getAd" ascii wide nocase
        $n6 = "c_tracking_pixel_gdpr" ascii wide
    condition:
        filesize < 5MB and ($n1 or $n2 or $n3 or $n4 or $n5 or $n6)
}
