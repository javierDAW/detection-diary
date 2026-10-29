/*
  Title: LiteLLM 1.107.0 compromise - privcollect startup-hook files and tampered build files
  Author: Jarmi
  Date: 2026-10-29
  Reference: https://www.wiz.io/blog/litellm-compromised-steals-credentials
  Scope: cook.pth, the sitecustomize.py loader / cook.py stealer and build-file tampering from the poisoned litellm 1.107.0 release (PyPI wheels and GHCR / Docker Hub images,
  2026-10-21). cook.py is stored obfuscated, so the stealer rule keys on the strings that survive in the loader and on runtime markers rather than on the decoded body. Rules were written
  from published descriptions; no sample was available to the author, so they were not run against the real files. Use the SHA-256 list in iocs.csv for exact matching.
*/

rule LiteLLM_1_107_0_Cook_Pth_Startup_Hook
{
    meta:
        author = "Jarmi"
        description = "Tiny .pth file whose only content is the import cook line used as a Python startup hook"
        date = "2026-10-29"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/"
        confidence = "medium"
        family = "LiteLLM 1.107.0 privcollect"
    strings:
        $hook = "import cook" ascii
    condition:
        filesize < 64 and $hook at 0
}

rule LiteLLM_1_107_0_Sitecustomize_Loader_Or_Cook_Stealer
{
    meta:
        author = "Jarmi"
        description = "Python startup file with the dead-drop, lock-file, run-once marker or exfiltration markers of the privcollect loader and stealer"
        date = "2026-10-29"
        reference = "https://www.wiz.io/blog/litellm-compromised-steals-credentials"
        confidence = "medium"
        family = "LiteLLM 1.107.0 privcollect"
    strings:
        $drop = "letters9813/pythonclient-test" ascii wide
        $lock = "/tmp/remote_code_loader.lock" ascii wide
        $once = ".pc_once_72129118c59f5636c0bb" ascii wide
        $env = "PRIVCOLLECT_ACTIVE" ascii wide
        $exfil = "litellm.dev/healthcheck" ascii wide
        $tok = "XWiA8gZNa7NcX2XRoAEb" ascii wide
        $table = "LiteLLM_CredentialsTable" ascii wide
        $codepy = "/codepy" ascii wide
    condition:
        filesize < 2MB and (($drop or $lock or $once or $env or $exfil or $tok) or ($table and $codepy))
}

rule LiteLLM_1_107_0_Tampered_Build_Files
{
    meta:
        author = "Jarmi"
        description = "pyproject.toml or Dockerfile carrying the two build edits that bundled the cook payload into the wheel and images"
        date = "2026-10-29"
        reference = "https://www.wiz.io/blog/litellm-compromised-steals-credentials"
        confidence = "medium"
        family = "LiteLLM 1.107.0 privcollect"
    strings:
        $py = "data = \"cook\"" ascii
        $docker = "COPY cook ./cook" ascii
    condition:
        filesize < 1MB and ($py or $docker)
}
