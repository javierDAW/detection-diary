/*
   Albiriox Android Banking RAT — heuristic for the unpacked DEX inside the APK.

   Strategy:
     - Anchor on the DEX magic at offset 0 (DEX file or extracted classes.dex).
     - Require AccessibilityService and the gesture-dispatch / node-tree primitives
       that drive Albiriox's self-grant chain and AcVNC.
     - Require either the AcVNC marker string or one of the operator command
       strings (blackscreen:on / blackscreen:off).
     - Require the AppInfos class name and at least two known banking or wallet
       package strings.
     - Cap filesize to 50 MB to keep scans cheap.

   This is a heuristic. Combine with MTD telemetry-based Sigma/KQL rules in the
   sibling folders for high-confidence detection.

   Author: Jarmi
*/

rule Albiriox_Android_Banking_RAT_2026
{
    meta:
        author = "Jarmi"
        description = "Heuristic for Albiriox Android MaaS — DEX header + AccessibilityService gesture chain + AcVNC marker + AppInfos class + 2 of N target packages"
        date = "2026-05-09"
        reference = "https://www.cleafy.com/cleafy-labs/albiriox-rat-mobile-malware-targeting-global-finance-and-crypto-wallets"
        confidence = "medium"
        family = "Albiriox"
    strings:
        $dex      = { 64 65 78 0A 30 33 35 00 }       // dex\n035\0
        $svc      = "android/accessibilityservice/AccessibilityService"
        $disp     = "dispatchGesture"
        $node     = "AccessibilityNodeInfo"
        $bounds   = "getBoundsInScreen"
        $type_ovr = "TYPE_APPLICATION_OVERLAY"
        $acvnc    = "AcVNC"
        $blkon    = "blackscreen:on"
        $blkoff   = "blackscreen:off"
        $appinfo  = "AppInfos"
        $tgt1     = "com.bbva.bbvacontigo"
        $tgt2     = "io.metamask"
        $tgt3     = "com.binance.dev"
        $tgt4     = "com.coinbase.android"
        $tgt5     = "com.santander.app"
        $tgt6     = "com.bitget.exchange"
        $tgt7     = "io.trustwallet.app"
        $tgt8     = "app.phantom"
    condition:
        $dex at 0
        and $svc and $disp and $node and $bounds and $type_ovr
        and ($acvnc or $blkon or $blkoff)
        and $appinfo
        and 2 of ($tgt*)
        and filesize < 50MB
}
