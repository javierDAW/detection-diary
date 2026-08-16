/*
   MicroLogix Lockout - July/August 2026 US water and wastewater sector PLC reconfiguration campaign.
   Two defensive rules for staging artifacts, not for the (non-existent) campaign malware:
     1. Rockwell SLC 500 / MicroLogix project artifacts found outside the sanctioned project repository.
     2. Generic EtherNet/IP - CIP reconnaissance and interaction tooling (scripts or small binaries).
   Both are triage aids for engineering workstations and jump hosts, not high-confidence malware signatures.
   Author: Jarmi
*/

rule Rockwell_SLC500_MicroLogix_Project_Artifact_2026
{
    meta:
        author = "Jarmi"
        description = "Rockwell SLC 500 / MicroLogix (RSLogix 500) project artifact - flag when staged outside the approved project repository"
        date = "2026-08-16"
        reference = "https://www.fbi.gov/investigate/cyber/alerts/2026/malicious-cyber-actors-targeting-water-and-wastewater-sector-internet--facing-programmable-logic-controllers-causing-operational-disruptions"
        confidence = "low"
        family = "ot-engineering-artifact"

    strings:
        $ole   = { D0 CF 11 E0 A1 B1 1A E1 }
        $p1    = "RSLogix 500" ascii nocase
        $p2    = "RSLogix500" ascii nocase
        $p3    = "SLC 500" ascii nocase
        $p4    = "MicroLogix" ascii nocase
        $p5    = "Bul.1766" ascii nocase
        $p6    = "Bul.1763" ascii nocase
        $l1    = "LadderFile" ascii nocase
        $l2    = "RungComment" ascii nocase
        $l3    = "DataTableFile" ascii nocase

    condition:
        uint32be(0) != 0x7F454C46 and
        filesize < 40MB and
        ($ole at 0 or $p1 or $p2) and
        ($p3 or $p4 or $p5 or $p6 or $l1 or $l2 or $l3)
}

rule EtherNetIP_CIP_Recon_Tooling_2026
{
    meta:
        author = "Jarmi"
        description = "Generic EtherNet/IP - CIP enumeration or interaction tooling: List Identity probing, port 44818 constants and CIP service names"
        date = "2026-08-16"
        reference = "https://www.forescout.com/blog/ot-security-analysis-exposed-devices-attacked-in-us-water-systems/"
        confidence = "low"
        family = "ot-recon-tooling"

    strings:
        $s1 = "44818" ascii
        $s2 = "ListIdentity" ascii nocase
        $s3 = "List Identity" ascii nocase
        $s4 = "RegisterSession" ascii nocase
        $s5 = "SendRRData" ascii nocase
        $s6 = "UnconnectedSend" ascii nocase
        $s7 = "Forward_Open" ascii nocase
        $s8 = "Get_Attribute_All" ascii nocase
        $s9 = "Set_Attribute_Single" ascii nocase
        $t1 = "enip" ascii nocase
        $t2 = "cpppo" ascii nocase
        $t3 = "pycomm3" ascii nocase
        $t4 = "plcscan" ascii nocase

    condition:
        filesize < 8MB and
        $s1 and
        ($s2 or $s3 or $s4 or $s5 or $s6 or $s7 or $s8 or $s9) and
        ($t1 or $t2 or $t3 or $t4)
}
