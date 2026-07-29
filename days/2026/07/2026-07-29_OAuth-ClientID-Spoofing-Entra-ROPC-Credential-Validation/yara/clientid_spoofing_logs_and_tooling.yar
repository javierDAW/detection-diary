/*
   OAuth client ID spoofing (Entra ID ROPC credential validation) - Proofpoint 2026-07-14.
   These rules are text/artifact rules, NOT malware-binary rules: this technique has no sample.
   Rule 1 flags EXPORTED Entra sign-in JSON records exhibiting the spoofing signature
   (AADSTS700016 with an empty appDisplayName). Rule 2 flags ROPC credential-checking TOOLING
   / PoC scripts that spray login.microsoftonline.com with spoofed client_id values.
   Author: Jarmi
*/

rule ClientIDSpoofing_SignInLog_Signature
{
    meta:
        author = "Jarmi"
        description = "Exported Entra ID sign-in JSON record showing OAuth client ID spoofing (AADSTS700016 with blank appDisplayName)"
        date = "2026-07-29"
        reference = "https://www.proofpoint.com/us/blog/threat-insight/oauth-client-id-spoofing-why-fake-client-ids-are-gaining-traction-stealthy"
        confidence = "medium"
        family = "ClientIDSpoofing-Entra-ROPC"
    strings:
        $err700016 = "700016" ascii wide
        $aadsts = "AADSTS700016" ascii wide
        $blankapp1 = "\"appDisplayName\":\"\"" ascii wide
        $blankapp2 = "\"appDisplayName\": \"\"" ascii wide
        $appid = "\"appId\"" ascii wide
        $ropc = "ropc" ascii wide nocase
    condition:
        filesize < 20MB and
        $appid and
        ($err700016 or $aadsts) and
        ($blankapp1 or $blankapp2) and
        $ropc
}

rule ClientIDSpoofing_ROPC_Checker_Tooling
{
    meta:
        author = "Jarmi"
        description = "ROPC credential-validation / client_id spoofing tooling or PoC targeting Entra ID token endpoint"
        date = "2026-07-29"
        reference = "https://thehackernews.com/2026/07/oauth-client-id-spoofing-lets-attackers.html"
        confidence = "medium"
        family = "ClientIDSpoofing-Entra-ROPC"
    strings:
        $endpoint = "login.microsoftonline.com" ascii wide
        $grant = "grant_type=password" ascii wide nocase
        $clientid = "client_id" ascii wide nocase
        $exchprefix = "00000002-0000-0ff1-ce00-" ascii wide nocase
        $ua = "python-requests" ascii wide nocase
        $token = "/oauth2/v2.0/token" ascii wide nocase
        $token_v1 = "/oauth2/token" ascii wide nocase
    condition:
        filesize < 2MB and
        $endpoint and $grant and $clientid and
        ($exchprefix or $ua or $token or $token_v1)
}
