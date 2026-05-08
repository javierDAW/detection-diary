# ADX free-cluster harness for KQL regression

This folder ships three Kusto scripts that let you replay every KQL rule in the
diary against handcrafted synthetic data, in a free Azure Data Explorer cluster
that does **not** require an Azure subscription.

| File | Role |
|---|---|
| `adx_bootstrap.kql` | Provisions the Defender XDR + Sentinel tables the diary's KQL queries reference (idempotent — it drops and re-creates the schema). |
| `adx_seed.kql` | Inserts handcrafted positive and negative rows for every rule, one block per day. |
| `adx_tests.kql` | Wraps each rule, counts hits, and prints a `PASS` / `FAIL` row per rule. |

## One-time setup

1. Open <https://dataexplorer.azure.com>.
2. Click **Add cluster** → **Free cluster** → sign in with any Microsoft account
   (a personal Outlook / Hotmail address is fine — no Azure subscription, no card).
3. Wait ~1 minute for provisioning. The default database is named `mykustodb`
   under the cluster `<your-handle>.kusto.windows.net/free`.
4. Open a query window pointing at that database.

## Per-run loop

```text
adx_bootstrap.kql        # once, or whenever you change the schema
adx_seed.kql             # before every test pass — resets the seed rows
adx_tests.kql            # the assertion run; every row should report PASS
```

Paste each file's content in order and execute. The final query in
`adx_tests.kql` returns one row per rule:

```
rule                                   expected  hits  status
day01_systembc_tcp_beacon              1         1     PASS
day02_shai_hulud_repo_create           1         1     PASS
...
```

A `FAIL` row means either the rule logic regressed or the seed needs to be
adjusted. Update **both** when you intentionally change a rule.

## Limitations

- The schemas only contain the columns the diary queries actually reference.
  Add columns to `adx_bootstrap.kql` if you write new queries that need them.
- Sentinel-only operators (`SecurityAlert`, `Heartbeat`, `Watchlist`) are not
  modelled. Any query that depends on them is exercised in Sentinel directly.
- The free cluster has a soft cap of ~1 GB of storage. The seed data here is
  well under 100 KB, so reseeding daily is cheap.

## Sentinel parity notes

ADX and Sentinel share the same Kusto engine. Operators we use in the diary
(`summarize`, `bin()`, `arg_max`, `join kind=inner`, `let`, `extend`,
`materialize`, `mv-expand`, `ipv4_is_in_range`, `extract`, `parse_json`,
`datetime_diff`) all behave identically. The only Sentinel-specific surface we
do not exercise here is the security solution functions (`_GetWatchlist`,
`AlertEvidence`, `BehaviorAnalytics`); none of the diary's published rules use
them today.
