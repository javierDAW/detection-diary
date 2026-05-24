/*
   Title:        First VPN Service client configuration and OpenVPN profile artifacts
   Author:       Jarmi
   Date:         2026-05-24
   Reference:    https://www.ic3.gov/CSA/2026/260521.pdf
   Reference:    https://www.europol.europa.eu/media-press/newsroom/news/cybercriminal-vpn-used-ransomware-actors-dismantled-in-global-crackdown
   Reference:    https://thehackernews.com/2026/05/first-vpn-dismantled-in-global-takedown.html
   Description:  Detects on-disk configuration artifacts left by clients of the seized
                 First VPN Service. Covers downloaded OpenVPN .ovpn profiles, WireGuard
                 .conf files, VLess+Reality (XTLS) client config blobs, and Outline
                 configuration JSON. Anchors include the seized domain set and the
                 customer-support communication accounts. Intended as a forensic
                 artifact-discovery rule, not a high-volume network rule.
   Confidence:   high
   Family:       first_vpn_service
*/

import "math"

rule first_vpn_service_client_config_2026 : firstvpn forensic
{
    meta:
        author = "Jarmi"
        date = "2026-05-24"
        description = "Detects First VPN Service client configuration artifacts on disk (OpenVPN, WireGuard, VLess+Reality, Outline) anchored on seized domains and support accounts"
        reference = "https://www.ic3.gov/CSA/2026/260521.pdf"
        confidence = "high"
        family = "first_vpn_service"
        version = "1"

    strings:
        // seized customer-facing domains
        $d1 = "1vpns.com" ascii nocase
        $d2 = "1vpns.net" ascii nocase
        $d3 = "1vpns.org" ascii nocase
        $d4 = "1jabber.com" ascii nocase

        // customer-support communication accounts
        $s1 = "support@1vpns.com" ascii nocase
        $s2 = "1vpns@1jabber.com" ascii nocase
        $s3 = "@FVPNS" ascii
        $s4 = "t.me/FirstVPNService" ascii nocase
        $s5 = "FirstVPNService" ascii

        // OpenVPN profile anchors specific to a commercial paid VPN with multi-hop
        $ovpn1 = "remote 1vpns" ascii nocase
        $ovpn2 = "auth-user-pass" ascii nocase
        $ovpn3 = "client" ascii
        $ovpn4 = "verb 3" ascii

        // WireGuard config anchors
        $wg1 = "[Interface]" ascii
        $wg2 = "[Peer]" ascii
        $wg3 = "Endpoint = " ascii

        // VLess + Reality protocol anchors (XTLS-Xray)
        $vless1 = "vless://" ascii
        $vless2 = "\"reality-opts\"" ascii
        $vless3 = "\"flow\":\"xtls-rprx-vision\"" ascii
        $vless4 = "\"network\":\"tcp\"" ascii
        $vless5 = "\"security\":\"reality\"" ascii

        // Outline server-config (Shadowsocks SIP002) anchor
        $out1 = "ss://" ascii
        $out2 = "outline-server" ascii nocase

    condition:
        // Either two domain anchors plus any communication-account anchor (high-confidence forensic),
        // or one domain anchor plus protocol-specific anchors clustered (config blob).
        filesize < 256KB and
        (
            (2 of ($d*) and any of ($s*)) or
            (1 of ($d*) and 2 of ($ovpn*)) or
            (1 of ($d*) and 2 of ($wg*)) or
            (1 of ($d*) and 2 of ($vless*)) or
            (1 of ($d*) and 1 of ($out*))
        )
}
