/*
  Title: Silent Ransom Group leaked-chat infrastructure strings in files and logs
  Author: Jarmi
  Date: 2026-10-20
  Reference: https://www.guidepointsecurity.com/blog/silent-ransom-group-leaked-chats/
  Scope: text-like artefacts (mail exports, proxy and DNS logs, shell history, rclone and SSH configurations, browser exports). There is no public malware
  sample: the Silent Ransom Group chats describe people, legitimate remote-access tools and rented servers, and GuidePoint GRIT reports that no encryptor
  or custom malware was observed. The rules therefore match published infrastructure strings only. They were not run against a real artefact, and
  GuidePoint marks the indicators as retrospective, so a hit is a lead that needs the date and the address holder at that time.
*/

rule SRG_Leak_Domain_Strings_In_Text_Artefacts
{
    meta:
        author = "Jarmi"
        description = "Text artefact that contains a Rocket.Chat server domain or a pretext domain from the GuidePoint GRIT appendix on the Silent Ransom Group chat leak"
        date = "2026-10-20"
        reference = "https://www.guidepointsecurity.com/blog/silent-ransom-group-leaked-chats/"
        confidence = "low"
        family = "SilentRansomGroup"
    strings:
        $d1 = "aim6umein3kee.com" ascii wide nocase
        $d2 = "slplsskdj2836v2jjsx.com" ascii wide nocase
        $d3 = "sokolovsky-law.com" ascii wide nocase
        $d4 = "ominetdata.com" ascii wide nocase
        $d5 = "develevenor.com" ascii wide nocase
        $d6 = "funconnect.com" ascii wide nocase
    condition:
        filesize < 50MB and ($d1 or $d2 or $d3 or $d4 or $d5 or $d6)
}

rule SRG_Leak_Staging_Host_In_Transfer_Config
{
    meta:
        author = "Jarmi"
        description = "Rclone, SSH, WinSCP or RDP configuration that points at a staging or RDP host listed in the GuidePoint GRIT appendix on the Silent Ransom Group chat leak"
        date = "2026-10-20"
        reference = "https://www.guidepointsecurity.com/blog/silent-ransom-group-leaked-chats/"
        confidence = "low"
        family = "SilentRansomGroup"
    strings:
        $ip1 = "199.217.98.21" ascii wide
        $ip2 = "216.203.20.157" ascii wide
        $ip3 = "45.32.232.133" ascii wide
        $ip4 = "87.251.67.222" ascii wide
        $ip5 = "87.251.67.223" ascii wide
        $ip6 = "66.179.31.122" ascii wide
        $ctx1 = "[" ascii
        $ctx2 = "host" ascii nocase
        $ctx3 = "HostName" ascii
        $ctx4 = "full address" ascii nocase
        $ctx5 = "sftp" ascii nocase
    condition:
        filesize < 2MB and ($ip1 or $ip2 or $ip3 or $ip4 or $ip5 or $ip6) and ($ctx1 or $ctx2 or $ctx3 or $ctx4 or $ctx5)
}
