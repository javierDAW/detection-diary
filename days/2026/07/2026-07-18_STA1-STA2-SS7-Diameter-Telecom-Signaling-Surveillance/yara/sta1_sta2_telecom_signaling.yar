/*
   STA1 / STA2 SS7 and Diameter telecom-signalling surveillance artefacts
   Author: Jarmi  -  2026-07-18
   These rules match TEXT/BINARY exports of signalling-firewall logs, PCAP-derived SMS PDU
   dumps, or SIEM case notes -- there is NO compiled malware binary in this case: the
   "malware" is protocol abuse of legitimate SS7/Diameter infrastructure. Scope accordingly:
   run these against exported log bundles, PCAP text dumps, or DFIR case-file text, not
   against arbitrary executables. Source: Citizen Lab Report No. 192 "Bad Connection"
   (Gary Miller and Swantje Lange, 2026-04-23); Enea SIMjacker disclosure (2019).
*/

rule STA1_Diameter_GhostOperator_Hostnames
{
    meta:
        author = "Jarmi"
        description = "STA1 Diameter Origin-Host / Route-Record hostnames documented as Ghost Operator entry points (Tango Networks UK, 019Mobile Israel, AIS Thailand DEA, Airtel Jersey)"
        date = "2026-07-18"
        reference = "https://citizenlab.ca/research/uncovering-global-telecom-exploitation-by-covert-surveillance-actors/"
        confidence = "high"
        family = "STA1-BadConnection"
    strings:
        $h1 = "cst001.epc.mnc053.mcc234.3gppnetwork.org" ascii
        $h2 = "ideabpl1h.epc.mnc019.mcc425.3gppnetwork.org" ascii
        $h3 = "ideabpl1h.dea.epc.mnc003.mcc520.3gppnetwork.org" ascii
        $h4 = "dra1.je211.epc.mnc003.mcc234.3gppnetwork.org" ascii
        $h5 = "vdrap1.epc.mnc019.mcc425.3gppnetwork.org" ascii
        $h6 = "vmdra01.epc.mnc019.mcc425.3gppnetwork.org" ascii
    condition:
        filesize < 50MB and ($h1 or $h2 or $h3 or $h4 or $h5 or $h6)
}

rule STA1_SS7_Recon_To_ATI_Escalation_Opcodes
{
    meta:
        author = "Jarmi"
        description = "STA1 SS7 MAP opcode sequence (recon SRI-SM/PSI escalating to anyTimeInterrogation) as it appears in exported signalling-firewall session logs"
        date = "2026-07-18"
        reference = "https://citizenlab.ca/research/uncovering-global-telecom-exploitation-by-covert-surveillance-actors/"
        confidence = "high"
        family = "STA1-BadConnection"
    strings:
        $recon1 = "sendRoutingInfoForSM" ascii
        $recon2 = "provideSubscriberInfo" ascii
        $escalate = "anyTimeInterrogation" ascii
        $gt1 = "855183901014" ascii
        $gt2 = "25882200300" ascii
        $gt3 = "467647531812" ascii
    condition:
        filesize < 50MB and $escalate and ($recon1 or $recon2) and (1 of ($gt1, $gt2, $gt3))
}

rule STA2_SIMjacker_Binary_SMS_PDU
{
    meta:
        author = "Jarmi"
        description = "STA2 SIMjacker-style binary SMS PDU markers (TP-PID=0x7F routed to SIM, TP-DCS=0x16 binary S@T-browser payload) as captured in a PCAP-derived SMS PDU text/hex export"
        date = "2026-07-18"
        reference = "https://www.enea.com/info/simjacker/"
        confidence = "high"
        family = "STA2-SIMjacker"
    strings:
        $pid_field = "TP-PID" ascii
        $pid_val = "127" ascii
        $dcs_field = "TP-DCS" ascii
        $dcs_val_dec = "TP-DCS=22" ascii
        $dcs_val_hex = "TP-DCS=0x16" ascii
        $op = "mt-ForwardSM" ascii
        $pdu_bytes = { 7F 16 }
    condition:
        filesize < 50MB and $op and $pid_field and (
            $dcs_val_dec or $dcs_val_hex or ($dcs_field and $pid_val) or $pdu_bytes
        )
}
