/*
   Payroll Pirates (Storm-2755 overlap) - AiTM phishing kit artifacts
   Author: Jarmi
   These rules target CAPTURED page/JavaScript artifacts of the AiTM toolkit
   (fingerprinting stage and proxied Microsoft sign-in page), NOT a confirmed
   binary. Intended for hunting saved HTML/JS pulled from phishing infrastructure
   or web proxy caches. Tune filesize as needed for your collection.
   Reference: https://arcticwolf.com/resources/blog/payroll-pirates-strange-new-tides-in-business-email-compromise/
*/

rule PayrollPirates_AiTM_Fingerprint_JS
{
    meta:
        author = "Jarmi"
        description = "Payroll Pirates AiTM fingerprinting stage: rcfh_country cookie, api.country.is geolocation, class_identifier.php submission path"
        date = "2026-08-12"
        reference = "https://arcticwolf.com/resources/blog/payroll-pirates-strange-new-tides-in-business-email-compromise/"
        confidence = "medium"
        family = "PayrollPirates-AiTM"
    strings:
        $cookie = "rcfh_country" ascii nocase
        $geo = "api.country.is" ascii nocase
        $path = "class_identifier.php" ascii nocase
        $stg = "/st_58200519/" ascii nocase
    condition:
        filesize < 300KB and $cookie and ($geo or $path or $stg)
}

rule PayrollPirates_AiTM_Proxy_Page_Rewrite
{
    meta:
        author = "Jarmi"
        description = "Payroll Pirates AiTM proxied Microsoft sign-in page: attacker domain prepended to full login.microsoftonline.com URLs and OpenResty frontend"
        date = "2026-08-12"
        reference = "https://arcticwolf.com/resources/blog/payroll-pirates-strange-new-tides-in-business-email-compromise/"
        confidence = "medium"
        family = "PayrollPirates-AiTM"
    strings:
        $rewrite = "/https://login.microsoftonline.com/common/" ascii nocase
        $gct = "GetCredentialType" ascii nocase
        $srv = "openresty/1.31.1.1" ascii nocase
    condition:
        filesize < 600KB and $rewrite and ($gct or $srv)
}
