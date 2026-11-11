/*
   Exposed Microsoft Entra application secrets and AI-provider API keys in source / config files
   (hygiene scanner related to the agentic AI secret-abuse activity reported by Microsoft)
   Author: Jarmi
   Date: 2026-11-11
   Reference: Microsoft Threat Intelligence 2026-11-05
              https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/
   Honesty: Microsoft published NO hashes, file names or byte patterns for this activity; these rules are
   NOT indicators of the campaign and say nothing about attribution. They find the material the agentic
   framework hunted for on GitHub: Entra client secrets (documented format: 3 characters, the literal
   "8Q~", then 34 characters from [A-Za-z0-9._~-]) next to client-secret variable names, and AI-provider /
   Azure OpenAI key variable names. Run them against repository clones, CI artefacts, container images and
   build outputs, then rotate whatever they find. Older Entra secrets use other formats and are NOT
   covered by the regex. A match is a credential-hygiene finding, not a compromise.
   Confidence: medium as a hygiene finding; low for attribution (none implied).
*/

rule Hygiene_Entra_Client_Secret_In_Text_File
{
    meta:
        author = "Jarmi"
        description = "Text, source or config file containing a value in the documented Microsoft Entra client secret format (xxx8Q~ + 34 chars) next to a client-secret variable name; credential-hygiene finding, not a campaign indicator"
        date = "2026-11-11"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/"
        confidence = "low"
        family = "Hygiene-ExposedSecret"
    strings:
        $secret = /[A-Za-z0-9_~.\-]{3}8Q~[A-Za-z0-9_~.\-]{34}/
        $kw_env = "AZURE_CLIENT_SECRET" ascii nocase
        $kw_snake = "client_secret" ascii nocase
        $kw_pascal = "ClientSecret" ascii nocase
        $kw_tenant = "tenant_id" ascii nocase
        $kw_tenant_env = "AZURE_TENANT_ID" ascii nocase
    condition:
        filesize < 5MB and
        uint16(0) != 0x5A4D and
        $secret and
        ($kw_env or $kw_snake or $kw_pascal or $kw_tenant or $kw_tenant_env)
}

rule Hygiene_AI_Provider_Or_Azure_Publishing_Credential_Names
{
    meta:
        author = "Jarmi"
        description = "Text, source or config file assigning a value to an AI-provider API key variable (OPENAI_API_KEY, ANTHROPIC_API_KEY, AZURE_OPENAI_API_KEY) or containing Azure App Service publishing-profile / storage connection-string credential fields; credential-hygiene finding, not a campaign indicator"
        date = "2026-11-11"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/"
        confidence = "low"
        family = "Hygiene-ExposedSecret"
    strings:
        $ai_openai = /OPENAI_API_KEY["']?\s*[:=]\s*["']?[A-Za-z0-9_\-]{20,}/
        $ai_anthropic = /ANTHROPIC_API_KEY["']?\s*[:=]\s*["']?[A-Za-z0-9_\-]{20,}/
        $ai_azure = /AZURE_OPENAI_API_KEY["']?\s*[:=]\s*["']?[A-Za-z0-9]{20,}/
        $pub_profile = "publishProfile" ascii
        $pub_pwd = "userPWD=\"" ascii
        $stor_conn = /AccountKey=[A-Za-z0-9+\/]{60,}={0,2}/
    condition:
        filesize < 5MB and
        uint16(0) != 0x5A4D and
        (
            $ai_openai or $ai_anthropic or $ai_azure or $stor_conn or
            ($pub_profile and $pub_pwd)
        )
}
