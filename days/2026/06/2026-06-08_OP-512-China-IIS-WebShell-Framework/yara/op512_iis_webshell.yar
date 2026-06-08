/*
   OP-512 IIS web shell framework - structural/heuristic rules
   Author: Jarmi
   These rules are HEURISTIC and STRUCTURAL, not sample-specific. OP-512's framework
   is generated per deployment by a builder that randomizes variable/method names and
   injects junk, so no stable hash exists. The rules target the API combination that
   the .ashx crypto command handlers (RC4 + RSA signature verification + IHttpHandler)
   and the .aspx self-report file manager (DNS/HTTP beacon + timestomp) must use to
   function. Expect false positives on legitimate ASP.NET code that uses cryptography;
   pair with the behavioral Sigma/KQL/Suricata content. Scope to text-based web content.
   Reference: https://reliaquest.com/blog/threat-spotlight-reliaquests-agentic-ai-uncovers-new-china-linked-cluster-op-512/
*/

rule OP512_Ashx_Crypto_Command_Handler
{
    meta:
        author      = "Jarmi"
        description = "Heuristic: ASP.NET .ashx handler combining RC4, RSA signature verification and reflection - matches the OP-512 cryptographically-authenticated command handler structure"
        date        = "2026-06-08"
        reference   = "https://reliaquest.com/blog/threat-spotlight-reliaquests-agentic-ai-uncovers-new-china-linked-cluster-op-512/"
        confidence  = "medium"
        family      = "OP-512 IIS web shell framework"
    strings:
        $h1 = "IHttpHandler" ascii wide
        $h2 = "ProcessRequest" ascii wide
        $rsa1 = "RSACryptoServiceProvider" ascii wide
        $rsa2 = "VerifyData" ascii wide
        $rsa3 = "VerifyHash" ascii wide
        $rc4_b64 = "FromBase64String" ascii wide
        $refl = "Assembly.Load" ascii wide
        $invoke = "Invoke" ascii wide
    condition:
        filesize < 200KB and
        ($h1 or $h2) and
        ($rsa1 or $rsa2 or $rsa3) and
        $rc4_b64 and
        ($refl or $invoke)
}

rule OP512_Aspx_SelfReport_FileManager
{
    meta:
        author      = "Jarmi"
        description = "Heuristic: ASP.NET .aspx file manager that resolves DNS / issues web requests and timestomps surrounding files - matches the OP-512 self-reporting file-manager web shell"
        date        = "2026-06-08"
        reference   = "https://gbhackers.com/china-linked-espionage-aspx-ashx-shells/"
        confidence  = "medium"
        family      = "OP-512 IIS web shell framework"
    strings:
        $page = "Page_Load" ascii wide
        $dns1 = "Dns.GetHostEntry" ascii wide
        $dns2 = "Dns.GetHostAddresses" ascii wide
        $http = "HttpWebRequest" ascii wide
        $ts1 = "SetCreationTime" ascii wide
        $ts2 = "SetLastWriteTime" ascii wide
        $fileops = "Directory.GetFiles" ascii wide
        $b64 = "ToBase64String" ascii wide
    condition:
        filesize < 200KB and
        $page and
        ($dns1 or $dns2 or $http) and
        ($ts1 or $ts2) and
        ($fileops or $b64)
}
