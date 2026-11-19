/*
  Title: agent-framework 1.26.1 / 1.26.2 PyPI compromise - .pth startup hook and runtime-diagnostics collector
  Author: Jarmi
  Date: 2026-11-19
  Reference: https://github.com/microsoft/agent-framework/issues/10411
  Scope: agent_framework_meta.pth / agent_framework_meta/_telemetry.py (1.26.1) and af_runtime_diag.pth / af_runtime_diag.py (1.26.2).
  Strings are inferred from public write-ups (SecurityWeek, Orca Security, GBHackers citing Socket); no sample was analysed by the author and the rules were not run against
  the real files. Use the SHA-256 values in iocs.csv for exact matching of the 1.26.2 files.
*/

rule AgentFramework_PyPI_Pth_Startup_Hook
{
    meta:
        author = "Jarmi"
        description = "Small .pth startup file that imports the agent_framework_meta or af_runtime_diag module added by malicious agent-framework 1.26.1 / 1.26.2"
        date = "2026-11-19"
        reference = "https://github.com/microsoft/agent-framework/issues/10411"
        confidence = "low"
        family = "agent-framework 1.26.x runtime-diagnostics stealer"
    strings:
        $imp = "import " ascii
        $m1 = "agent_framework_meta" ascii
        $m2 = "af_runtime_diag" ascii
    condition:
        filesize < 1KB and $imp and ($m1 or $m2)
}

rule AgentFramework_PyPI_Runtime_Diagnostics_Collector
{
    meta:
        author = "Jarmi"
        description = "Python collector of the malicious agent-framework 1.26.1 / 1.26.2 releases: re-execution guard, module names, User-Agent strings and webhook.site exfiltration"
        date = "2026-11-19"
        reference = "https://github.com/microsoft/agent-framework/issues/10411"
        confidence = "low"
        family = "agent-framework 1.26.x runtime-diagnostics stealer"
    strings:
        $guard = "_AF_TEL" ascii wide
        $ua1 = "af-runtime-diagnostics/1" ascii wide
        $ua2 = "runtime-diagnostics/1" ascii wide
        $hook = "webhook.site" ascii wide
        $mod1 = "af_runtime_diag" ascii wide
        $mod2 = "agent_framework_meta" ascii wide
        $tel = "_telemetry" ascii wide
    condition:
        filesize < 500KB and ($guard or $ua1 or ($ua2 and $hook) or ($hook and ($mod1 or $mod2 or $tel)))
}
