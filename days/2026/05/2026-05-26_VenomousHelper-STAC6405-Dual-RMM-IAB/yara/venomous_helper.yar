/*
 * VENOMOUS#HELPER / STAC6405 — JWrapper-packaged SimpleHelp + ScreenConnect
 * Anchors on the JWrapper bundle structure, the SimpleHelp campaign tenant
 * identifier (sh_app_profile), the watchdog liveness filename (sgalive), the
 * hex-encoded C2 launch property (sg_servers), and the ScreenConnect install
 * GUID (adbce2b92cb435b3) reused across victims. Designed to hit on the
 * dropped installation tree and on the JWrapper installer PE itself.
 * Reference: Securonix 2026-05-04 + The Hacker News 2026-05-04.
 */

rule VENOMOUS_HELPER_STAC6405_JWrapper_SimpleHelp_ScreenConnect
{
    meta:
        author      = "Jarmi"
        description = "VENOMOUS#HELPER / STAC6405 dual-RMM IAB campaign: JWrapper SimpleHelp + ScreenConnect anchors"
        date        = "2026-05-26"
        reference   = "https://www.securonix.com/blog/venomous-helper-phishing-campaign/"
        confidence  = "high"
        family      = "VENOMOUS#HELPER / STAC6405"

    strings:
        // SimpleHelp campaign tenant identifier — invariant across victims
        $sh_profile = "43794105415826700294423976831165084124" ascii wide

        // Watchdog liveness file name
        $sgalive    = "sgalive" ascii

        // JWrapper config marker — the hex-encoded C2 launch property
        $sg_servers = "sg_servers" ascii

        // SimpleHelp service / RAT artifact names
        $svc_remote = "Remote Access Service" ascii wide
        $svc_sg     = "SimpleGatewayService" ascii
        $svc_smps   = "SimpleService" ascii
        $sess_win   = "session_win.exe" ascii
        $elev_win   = "elev_win.exe" ascii
        $mouseloc   = "--mouselocation" ascii

        // JWrapper directory anchors
        $dir_root   = "JWrapper-Remote Access" ascii wide
        $dir_share  = "JWAppsSharedConfig" ascii wide

        // ScreenConnect install-GUID anchor — invariant across victims
        $sc_guid    = "ScreenConnect Client (adbce2b92cb435b3)" ascii wide

        // ScreenConnect relay parameters
        $sc_relay   = "sslzeromail.run.place" ascii wide
        $sc_port    = "8041" ascii

        // SimpleHelp C2 host
        $sh_c2      = "84.200.205.233" ascii wide

        // Firewall exception name registered via netsh advfirewall
        $fw_name    = "SHRemoteAccessService" ascii wide

    condition:
        filesize < 200MB and (
            // Anchor on the SimpleHelp campaign tenant ID alone
            $sh_profile or
            // Or on the ScreenConnect GUID alone
            $sc_guid or
            // Or on multiple JWrapper-tree anchors together
            ( $dir_root and $dir_share and ($svc_remote or $svc_sg or $svc_smps) ) or
            // Or on the C2 host + at least one JWrapper artefact
            ( $sh_c2 and any of ($sgalive, $sg_servers, $sess_win, $elev_win, $mouseloc, $fw_name) ) or
            // Or on the ScreenConnect relay FQDN + port pair
            ( $sc_relay and $sc_port )
        )
}
