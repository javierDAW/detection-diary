/*
   Refrigeration supervisory controllers - Danfoss AK-SM 8xxA "StoreView" and Copeland XWEB Pro
   Author: Jarmi
   Date: 2026-11-07
   Reference: Claroty Team82 (2026-08-09) CVE-2025-41450 / CVE-2025-41451 / CVE-2025-41452 (Danfoss)
              and CVE-2026-25085 / CVE-2026-21718 / CVE-2026-24663 (Copeland); EFS cold-storage
              incident (Medical Device Network / NPR, 2026-11-06).
   There is NO malware, sample, hash or public PoC tied to the EFS incident, and no source shows
   these CVEs were used there. These are low-confidence ARTIFACT rules for files that reference
   the published controller API surface: scripts, request templates, notes, config exports,
   proxy captures or tool output found on jump hosts, VPN-reachable workstations, file shares or
   seized hacktivist tooling. Legitimate integration scripts and vendor documentation also match;
   a hit means "review who wrote this and why", not "compromised".
*/

rule Danfoss_StoreView_XmlCgi_API_Artifact
{
    meta:
        author = "Jarmi"
        description = "File referencing the Danfoss AK-SM StoreView xml.cgi API together with getauth or load_nginx_headers actions or the sm_fcgi_app backend (CVE-2025-41450 / CVE-2025-41452 surface)"
        date = "2026-11-07"
        reference = "https://claroty.com/team82/research/freeze-the-controller-defrost-the-food-uncovering-vulnerabilities-in-danfoss-refrigeration-controllers"
        confidence = "low"
        family = "refrigeration-controller-tooling"
    strings:
        $cgi = "xml.cgi" ascii wide nocase
        $getauth = "getauth" ascii wide
        $nginx_hdr = "load_nginx_headers" ascii wide
        $fcgi = "sm_fcgi_app" ascii wide
        $title1 = "Danfoss StoreView" ascii wide nocase
        $title2 = "StoreView Web" ascii wide nocase
        $hdrconf = "headers.conf" ascii wide
    condition:
        filesize < 2MB and $cgi and ($getauth or $nginx_hdr or $fcgi) and ($title1 or $title2 or $hdrconf or $nginx_hdr)
}

rule Copeland_XWEB_Pro_Shellinabox_Access_Artifact
{
    meta:
        author = "Jarmi"
        description = "File referencing Copeland XWEB Pro (XWEB300D / XWEB500D) together with Shellinabox or an HTTP Basic Authorization header (CVE-2026-21718 / CVE-2026-25085 surface)"
        date = "2026-11-07"
        reference = "https://claroty.com/team82/research/freeze-the-controller-defrost-the-food-uncovering-vulnerabilities-in-danfoss-refrigeration-controllers"
        confidence = "low"
        family = "refrigeration-controller-tooling"
    strings:
        $xweb = "XWEB" ascii wide
        $m300 = "XWEB300D" ascii wide nocase
        $m500 = "XWEB500D" ascii wide nocase
        $pro = "XWEB Pro" ascii wide nocase
        $siab = "shellinabox" ascii wide nocase
        $basic = "Authorization: Basic" ascii wide nocase
        $copeland = "Copeland" ascii wide nocase
    condition:
        filesize < 2MB and $xweb and ($m300 or $m500 or $pro or $copeland) and ($siab or $basic)
}
