/*
   MCPhantom - deprecated @modelcontextprotocol MCP server hints
   Author: Jarmi
   Date: 2026-11-04
   Reference: Glow Labs "MCPhantom" (2026-11) and Help Net Security (2026-11-03).
   Purpose: scan developer endpoints / repos / backups for text files (MCP client configs,
   lockfiles, package.json, npm cache metadata) that reference the archived, deprecated
   @modelcontextprotocol reference servers named by Glow Labs. These are hygiene / inventory
   rules, NOT malware signatures: the deprecated packages are legitimate code that will never
   be patched (server-puppeteer carries an unpatched high-severity RCE, no CVE/GHSA id).
   The "mcpServers" / "npx" / "-y" config shape is generic MCP client knowledge, not from the
   sources. Confidence: low, no technical IOC published.
*/

rule MCPhantom_MCP_Config_References_Deprecated_Server
{
    meta:
        author = "Jarmi"
        description = "MCP client config (JSON) with an mcpServers block launching a deprecated @modelcontextprotocol reference server via npx"
        date = "2026-11-04"
        reference = "https://www.glow.io/blogs/mcphantom-ai-coding-agents-are-installing-vulnerable-deprecated-mcp-servers-from-training-data"
        confidence = "low"
        family = "MCPhantom"
    strings:
        $cfg = "\"mcpServers\"" ascii wide
        $npx = "npx" ascii wide
        $y = "\"-y\"" ascii wide
        $p1 = "@modelcontextprotocol/server-github" ascii wide
        $p2 = "@modelcontextprotocol/server-postgres" ascii wide
        $p3 = "@modelcontextprotocol/server-slack" ascii wide
        $p4 = "@modelcontextprotocol/server-puppeteer" ascii wide
        $p5 = "@modelcontextprotocol/server-brave-search" ascii wide
        $p6 = "@modelcontextprotocol/server-google-maps" ascii wide
        $p7 = "@modelcontextprotocol/server-gitlab" ascii wide
        $p8 = "@modelcontextprotocol/server-gdrive" ascii wide
        $p9 = "@modelcontextprotocol/server-redis" ascii wide
        $p10 = "@modelcontextprotocol/create-server" ascii wide
        $p11 = "@modelcontextprotocol/server-aws-kb-retrieval" ascii wide
        $p12 = "@modelcontextprotocol/server-everart" ascii wide
    condition:
        filesize < 2MB and $cfg and ($npx or $y) and
        ($p1 or $p2 or $p3 or $p4 or $p5 or $p6 or $p7 or $p8 or $p9 or $p10 or $p11 or $p12)
}

rule MCPhantom_Package_Metadata_Deprecated_MCP_Server
{
    meta:
        author = "Jarmi"
        description = "Lockfile / package.json / npm cache metadata referencing a deprecated @modelcontextprotocol reference server together with a deprecation marker"
        date = "2026-11-04"
        reference = "https://www.helpnetsecurity.com/2026/11/03/mcphantom-deprecated-mcp-servers/"
        confidence = "low"
        family = "MCPhantom"
    strings:
        $dep = "deprecated" ascii wide nocase
        $q1 = "server-github" ascii wide
        $q2 = "server-postgres" ascii wide
        $q3 = "server-slack" ascii wide
        $q4 = "server-puppeteer" ascii wide
        $q5 = "server-brave-search" ascii wide
        $q6 = "server-google-maps" ascii wide
        $q7 = "server-gitlab" ascii wide
        $q8 = "server-gdrive" ascii wide
        $q9 = "server-redis" ascii wide
        $q10 = "create-server" ascii wide
        $q11 = "server-aws-kb-retrieval" ascii wide
        $q12 = "server-everart" ascii wide
        $scope = "@modelcontextprotocol" ascii wide
    condition:
        filesize < 2MB and $scope and $dep and
        ($q1 or $q2 or $q3 or $q4 or $q5 or $q6 or $q7 or $q8 or $q9 or $q10 or $q11 or $q12)
}
