# PEAK Hunt H1 - AI Agent or Developer Acted on the Fake requests-secure-v2 Lure

**Framework:** PEAK (Prepare, Execute, Act with Knowledge)
**Hypothesis:** If a browsing AI agent (or a developer following SEO-poisoned results) ingested the campaign-1 IPI content, then a host installed or tried to install the non-existent package `requests-secure-v2`, and/or resolved `py-lib-repository[.]dev` shortly before.

## Prepare

- **ATT&CK:** T1204 (User Execution), T1036.005 (Match Legitimate Name or Location), T1608.006 (SEO Poisoning).
- **Data sources:** EDR `DeviceProcessEvents`, shell/auditd `execve`, package-manager logs, DNS (Sysmon EID 22), proxy.
- **Scope:** AI-agent runner hosts and developer workstations first; then CI runners that resolve packages dynamically.

## Execute

```kql
// Any attempt to install the fake package name (Defender XDR)
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "requests-secure-v2"
| where ProcessCommandLine has_any ("pip install","pip3 install","uv pip install",
        "uv add","poetry add","pipenv install","-m pip install","pip download")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```

```bash
# On a suspect host: shell history and pip cache references to the fake name
grep -RIn 'requests-secure-v2' ~/.bash_history ~/.zsh_history ~/.cache/pip 2>/dev/null
# DNS/proxy correlation for the fake-library documentation host
grep -RIn 'py-lib-repository\.dev' /var/log 2>/dev/null
```

## Act with Knowledge

- **Confirmed malicious:** any real install attempt of `requests-secure-v2` - the package does not legitimately exist; the name is only an IPI/SEO lure. Preserve the agent transcript / tool-call log around the event.
- **Benign baseline:** an internal proxy or mirror that deliberately shadows the name to block it; confirm the resolved index host.
- **Feed forward:** the account/agent and its egress feed H2 (campaign infra) and H3 (payment attempt). If an agent transcript exists, capture the injected instruction verbatim for detection tuning.
