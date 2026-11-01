# PEAK hunt H1 - a developer or DevOps workstation reached a production service container that can request or authorize withdrawals

## Prepare

**Hypothesis.** If an operator controls a DevOps or SRE laptop, they will use the engineer's existing access (kubeconfig, cloud CLI sessions, container runtime access, CI credentials) to reach a production service container in the withdrawal pathway and run code or submit transactions from inside it. That leaves (a) credential-store reads or secret-export commands on the laptop by an unusual parent, (b) `kubectl exec` / `debug` / `cp` / `port-forward` or `docker exec` sessions into withdrawal-capable workloads from that laptop, and (c) control-plane audit records (Kubernetes `pods/exec`, cloud `ExecuteCommand`, run-command) tied to the engineer's identity at unusual times or from new sources.

**Why first.** Binance's first published finding for the 2026-10-29/30 hot-wallet drain (~USD 6.3B) was exactly this path: a compromised DevOps engineer's laptop gave access to a service container that submitted unauthorized withdrawal transactions. CEO Richard Teng later said it was more complex than a single one-click action and that additional breach points were found. The path from a human workstation to a container that can move funds is the narrowest choke point you control.

**What is not known.** Binance did not publish the laptop OS, malware or tool names, the credentials used, how signing authority was obtained, the additional breach points, or any IP, domain or hash. Binance says it found no evidence of a wallet private-key leak. One vendor blog speculated about fake job interviews and malicious Terraform lock files or registries; that is UNCORROBORATED and is used here only as a generic IaC check (Sigma 03, KQL k3). Nothing in this hunt keys on an indicator from the case.

**Scope.** Every identity (human, CI, service account) that can exec into, deploy to, or read secrets of a workload in the withdrawal pathway: withdrawal API, risk / approval service, transaction builder, signer, broadcaster, deposit-sweep jobs. Every workstation those humans use. Last 90 days.

**Data quality check first.** Confirm you have Kubernetes API audit logs at `Metadata` level or higher for `pods/exec`, `pods/attach`, `pods/portforward`, `pods/ephemeralcontainers`, `secrets`; cloud control-plane logs (CloudTrail, Azure Activity, GCP Admin Activity); and EDR process telemetry on the developer fleet.

## Execute

1. Build the access map: which RBAC bindings and cloud roles allow `create pods/exec` or secret reads in withdrawal-pathway namespaces, and which humans hold them. Anyone outside an on-call / break-glass group is a finding on its own.
2. Pull every exec / attach / port-forward / ephemeral-container event into those namespaces; join on user, source IP and user agent. First-seen source IPs, `kubectl` user agents from non-corporate ranges, and sessions outside change windows come first.
3. On the workstations behind those users, run Sigma 01 and KQL k1 (credential reads followed by egress), Sigma 02 (exec from workstation-class parent), Sigma 03 / KQL k3 (lock or registry config rewritten).
4. Inside the containers, look for shells or utilities reaching the metadata endpoint (Sigma 04) and for processes that are not the service binary.

```bash
# Author: Jarmi
# Read-only: who can exec into or read secrets in a withdrawal-pathway namespace. Replace <wallet_ns>.
kubectl auth can-i --list --namespace <wallet_ns> --as=<user_or_sa> | grep -E 'pods/exec|pods/attach|pods/portforward|secrets'
kubectl get rolebindings,clusterrolebindings -A -o json | \
  jq -r '.items[] | select(.roleRef.name|test("admin|edit|exec";"i")) | [.metadata.namespace // "cluster", .metadata.name, ([.subjects[]?.name]|join(","))] | @tsv'
# Kubernetes audit log (JSON lines) - exec / attach / port-forward / ephemeral containers into <wallet_ns>.
jq -c 'select(.objectRef.namespace=="<wallet_ns>" and (.objectRef.subresource|tostring|test("exec|attach|portforward|ephemeralcontainers")))
       | {ts:.requestReceivedTimestamp, user:.user.username, ip:.sourceIPs, ua:.userAgent, pod:.objectRef.name, sub:.objectRef.subresource}' \
  /var/log/kubernetes/audit/*.log
```

```kql
// Author: Jarmi
// AKS diagnostic logs in Sentinel: exec / attach / port-forward into withdrawal-pathway namespaces. Replace <wallet_ns>.
AzureDiagnostics
| where TimeGenerated > ago(90d)
| where Category == "kube-audit"
| extend a = parse_json(log_s)
| where tostring(a.objectRef.namespace) == "<wallet_ns>"
| where tostring(a.objectRef.subresource) in ("exec", "attach", "portforward", "ephemeralcontainers")
| project TimeGenerated, User = tostring(a.user.username), SourceIPs = tostring(a.sourceIPs), UserAgent = tostring(a.userAgent),
          Pod = tostring(a.objectRef.name), Sub = tostring(a.objectRef.subresource), Verb = tostring(a.verb)
| sort by TimeGenerated desc
```

**Expected benign.** On-call engineers debugging under an incident or change ticket; platform automation using a dedicated service account from a known runner range. Benign sessions have a ticket, a known source and a short duration.

## Act

- **Positive (exec into a withdrawal-pathway workload without a ticket, or from a new source, or preceded by credential reads on the laptop):** freeze withdrawals from the affected pathway with the business owner, revoke the user's cluster and cloud sessions and tokens, rotate every secret mounted in the touched pods, isolate the workstation with EDR and capture memory and disk, then run H3 for the same window.
- **Negative:** reduce standing exec rights in withdrawal namespaces to a just-in-time break-glass group, require hardware-key MFA for that group, and alert on every exec there (it should be rare enough to review by hand).
- **Escalate** to the incident commander and the custody / treasury owner; never let the investigated engineer's laptop keep its sessions while you investigate.

## Knowledge

Record the access map, the exec baseline per namespace and the rules used: [Sigma 01](../sigma/01_dev_workstation_cloud_cli_or_kube_credential_harvest_from_interpreter.yml), [Sigma 02](../sigma/02_kubectl_or_docker_exec_into_production_container_from_workstation.yml), [Sigma 03](../sigma/03_iac_lock_or_registry_config_written_outside_vcs_tooling.yml), [Sigma 04](../sigma/04_container_shell_reaching_cloud_metadata_endpoint.yml), [KQL k1](../kql/k1_workstation_cloud_credential_read_then_outbound.kql), [KQL k3](../kql/k3_lock_or_registry_config_written_by_non_vcs_process.kql), [Suricata](../suricata/binance_devops_egress.rules) (sids 9800002, 9800003), [YARA](../yara/binance_devops_workstation_artifacts.yar).
