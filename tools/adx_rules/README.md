# tools/adx_rules — one ADX-runnable file per detection rule

Each file under this directory is the literal body of a `days/*/kql/*.kql`
rule with its trailing `| sort` / `| project` / `| top` step removed and a
`| summarize hits = count()` appended. Paste any single file in the ADX
query window after running `adx_bootstrap.kql` and `adx_seed.kql`, and
click Run. Hits > 0 means the rule fired against the seed.

| Rule slug | Source file |
|---|---|
| `r_2026_04_28__tcp_beacon_no_tls_systembc` | `days/2026/04/2026-04-28_TheGentlemen-SystemBC/kql/tcp_beacon_no_tls_systembc.kql` |
| `r_2026_04_29__github_repo_create_shai_hulud` | `days/2026/04/2026-04-29_ShaiHulud-Bitwarden/kql/github_repo_create_shai_hulud.kql` |
| `r_2026_04_30__cisco_asa_reboot_webvpn_correlation` | `days/2026/04/2026-04-30_FIRESTARTER-LINE-VIPER-UAT4356/kql/cisco_asa_reboot_webvpn_correlation.kql` |
| `r_2026_05_01__vect_mass_process_kill` | `days/2026/05/2026-05-01_VECT-2.0-RaaS/kql/vect_mass_process_kill.kql` |
| `r_2026_05_02__x_hacked_by_waf` | `days/2026/05/2026-05-02_Nexcorium-TBK-DVR-CVE-2024-3721/kql/x_hacked_by_waf.kql` |
| `r_2026_05_03__engineering_tool_egress` | `days/2026/05/2026-05-03_BAUXITE-CyberAvengers-AA26-097A/kql/engineering_tool_egress.kql` |
| `r_2026_05_04__lsass_dump_via_taskmgr` | `days/2026/05/2026-05-04_C0063-Poland-Wiper/kql/lsass_dump_via_taskmgr.kql` |
| `r_2026_05_04__rubeus_s4u_tgs_burst` | `days/2026/05/2026-05-04_C0063-Poland-Wiper/kql/rubeus_s4u_tgs_burst.kql` |
| `r_2026_05_05__akira_recon_impacket_smb_burst` | `days/2026/05/2026-05-05_Akira-SonicWall-CVE-2024-40766/kql/akira_recon_impacket_smb_burst.kql` |
| `r_2026_05_05__sonicwall_vpn_anomalous_login` | `days/2026/05/2026-05-05_Akira-SonicWall-CVE-2024-40766/kql/sonicwall_vpn_anomalous_login.kql` |
| `r_2026_05_06__aitm_chain_correlation` | `days/2026/05/2026-05-06_CodeOfConduct-AiTM-Storm-1747/kql/aitm_chain_correlation.kql` |
| `r_2026_05_06__firstseen_attacker_domain_pdf` | `days/2026/05/2026-05-06_CodeOfConduct-AiTM-Storm-1747/kql/firstseen_attacker_domain_pdf.kql` |
| `r_2026_05_06__peak_h1_click_to_device` | `days/2026/05/2026-05-06_CodeOfConduct-AiTM-Storm-1747/kql/peak_h1_click_to_device.kql` |
| `r_2026_05_07__defender_credential_burst_dev_host` | `days/2026/05/2026-05-07_EVM-DeFi-npm-typosquat-namikazesarada/kql/defender_credential_burst_dev_host.kql` |
| `r_2026_05_07__sentinel_node_outbound_first_seen_ipv4` | `days/2026/05/2026-05-07_EVM-DeFi-npm-typosquat-namikazesarada/kql/sentinel_node_outbound_first_seen_ipv4.kql` |
| `r_2026_05_07__qlnx_credential_files_burst` | `days/2026/05/2026-05-07_QLNX-Quasar-Linux-RAT/kql/qlnx_credential_files_burst.kql` |
| `r_2026_05_07__qlnx_ipapi_geo_beacon` | `days/2026/05/2026-05-07_QLNX-Quasar-Linux-RAT/kql/qlnx_ipapi_geo_beacon.kql` |
| `r_2026_05_07__qlnx_ld_preload_modification` | `days/2026/05/2026-05-07_QLNX-Quasar-Linux-RAT/kql/qlnx_ld_preload_modification.kql` |
| `r_2026_05_07__qlnx_x11_lock_path_drop` | `days/2026/05/2026-05-07_QLNX-Quasar-Linux-RAT/kql/qlnx_x11_lock_path_drop.kql` |
| `r_2026_05_08__cloudz_pastebin_handle_hellohiall` | `days/2026/05/2026-05-08_CloudZ-RAT-Pheno-PhoneLink/kql/cloudz_pastebin_handle_hellohiall.kql` |
| `r_2026_05_08__cloudz_phone_db_to_workers_correlation` | `days/2026/05/2026-05-08_CloudZ-RAT-Pheno-PhoneLink/kql/cloudz_phone_db_to_workers_correlation.kql` |
