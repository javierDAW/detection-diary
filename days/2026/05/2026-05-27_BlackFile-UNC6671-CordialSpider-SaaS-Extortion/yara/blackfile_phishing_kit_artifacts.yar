/*
   blackfile_phishing_kit_artifacts.yar
   YARA rule set targeting phishing-kit / credential-harvester boilerplate
   patterns associated with UNC6671 / BlackFile / Cordial Spider, as
   documented by Google Threat Intelligence Group on 2026-05-15.

   These rules are intentionally conservative: GTIG did not publish a
   harvester source-code sample, so the rule anchors are derived from the
   public IOC anchors (Tucows-registered apex domains, scripting-library
   User-Agent strings, FedAuth-cookie-replay primitive) combined with
   common harvester boilerplate. False positives are possible against
   legitimate security training material; combine with environmental
   context before alerting.

   Author: Jarmi
   Date:   2026-05-27
*/

rule BlackFile_UNC6671_AiTM_Lookalike_Apex_References
{
    meta:
        author      = "Jarmi"
        description = "Detects file content referencing the UNC6671 / BlackFile Tucows-registered AiTM lookalike apex domains (enrollms[.]com, passkeyms[.]com, setupsso[.]com), typically found inside dropped phishing-kit ZIPs, harvester source files, or attacker-controlled web-app config files."
        date        = "2026-05-27"
        reference   = "https://cloud.google.com/blog/topics/threat-intelligence/blackfile-vishing-extortion-operation"
        family      = "blackfile"
        confidence  = "medium"

    strings:
        $apex_enrollms  = "enrollms.com" ascii nocase
        $apex_passkeyms = "passkeyms.com" ascii nocase
        $apex_setupsso  = "setupsso.com" ascii nocase
        $kit_login_form = "name=\"login\"" ascii nocase
        $kit_mfa_field  = "mfa_code" ascii nocase
        $kit_passkey    = "passkey" ascii nocase

    condition:
        filesize < 5MB
        and any of ($apex_*)
        and 2 of ($kit_*)
}

rule BlackFile_UNC6671_SaaS_Exfil_Script_Boilerplate
{
    meta:
        author      = "Jarmi"
        description = "Detects Python or PowerShell script content that combines the UNC6671 SaaS-exfil primitives: spoofed Microsoft Office ClientAppId, scripting-library User-Agent, FedAuth session-cookie replay, and SharePoint REST or Microsoft Graph file-download endpoint. Conservative rule for finding operator scripts dropped on a compromised endpoint or staged on attacker infrastructure."
        date        = "2026-05-27"
        reference   = "https://cloud.google.com/blog/topics/threat-intelligence/blackfile-vishing-extortion-operation"
        family      = "blackfile"
        confidence  = "medium"

    strings:
        $office_client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c" ascii nocase
        $ua_python        = "python-requests/" ascii
        $ua_powershell    = "WindowsPowerShell/5.1" ascii
        $cookie_fedauth   = "FedAuth" ascii nocase
        $api_sharepoint   = "/_api/web/" ascii nocase
        $api_download     = "/_layouts/15/download.aspx" ascii nocase
        $api_graph        = "graph.microsoft.com/v1.0/drives" ascii nocase

    condition:
        filesize < 1MB
        and (
            ($office_client_id and ($ua_python or $ua_powershell))
            or
            ($cookie_fedauth and ($api_sharepoint or $api_download or $api_graph))
        )
}

rule BlackFile_UNC6671_Extortion_Note_Subject_Template
{
    meta:
        author      = "Jarmi"
        description = "Detects the verbatim BlackFile / UNC6671 initial extortion-note subject template literally present inside a saved email file (.eml, .msg export), an extortion-tracking spreadsheet, or a phishing-kit configuration file. Subject pattern fixed per GTIG 2026-05-15."
        date        = "2026-05-27"
        reference   = "https://cloud.google.com/blog/topics/threat-intelligence/blackfile-vishing-extortion-operation"
        family      = "blackfile"
        confidence  = "high"

    strings:
        $subject_template = "DATA BREACH 72 HOURS TO CONTACT US" ascii nocase
        $brand_blackfile  = "BlackFile" ascii nocase
        $comms_session    = "getsession.org" ascii nocase
        $comms_tox        = "Tox ID" ascii nocase

    condition:
        filesize < 5MB
        and $subject_template
        and 1 of ($brand_blackfile, $comms_session, $comms_tox)
}
