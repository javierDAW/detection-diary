/*
   YARA — Neunative residential-proxy SDK (RoboVPN / Vo1d-Popa backend)
   Author: Jarmi
   Date:   2026-06-28
   Ref:    https://github.com/deepfield/public-research/blob/main/reports/2026-06-18-robovpn-neunative.md
   Note:   Targets the native x64 proxy SDK, its .NET shim, and host artifacts. The native
           binary exports a small fixed API and embeds the director string and TLV protocol
           markers; the .NET shim declares the same DllImports. Bound with filesize.
*/

rule Neunative_Native_Proxy_SDK
{
    meta:
        author      = "Jarmi"
        description = "Detects the NeunativeWin.dll native residential-proxy SDK by its exported API and director/registry markers"
        date        = "2026-06-28"
        reference   = "https://github.com/deepfield/public-research/blob/main/reports/2026-06-18-robovpn-neunative.md"
        confidence  = "high"
        family      = "Neunative/Vo1d-Popa"
        sha256      = "6f686ba628de3bf1ebfb8504e2e966334b02505c546bb9d2ad020f5f5d1d01b7"
    strings:
        $exp1 = "startNeuNative" ascii
        $exp2 = "stopNeuNative" ascii
        $exp3 = "setParameterString" ascii
        $exp4 = "setParameterInt" ascii
        $dir  = "gmslb.net" ascii nocase
        $reg  = "Software\\Neunative" ascii nocase
        $pdb  = "android-native-sdk" ascii nocase
        $regd = "/regdev" ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 8MB and
        ($exp1 or $exp2) and
        ($exp3 or $exp4 or $dir or $reg or $pdb or $regd)
}

rule Neunative_DotNet_Shim
{
    meta:
        author      = "Jarmi"
        description = "Detects the NeunativeNG.dll .NET P/Invoke shim over the native proxy SDK"
        date        = "2026-06-28"
        reference   = "https://github.com/deepfield/public-research/blob/main/reports/2026-06-18-robovpn-neunative.md"
        confidence  = "high"
        family      = "Neunative/Vo1d-Popa"
        sha256      = "74beab8ae664958742f6c5d33c1a50bd06d4137147e42c0b94b7be2f8ec98ebb"
    strings:
        $dll  = "NeunativeWin.dll" ascii wide
        $ng   = "NeunativeNG" ascii wide
        $i1   = "startNeuNative" ascii wide
        $i2   = "setParameterBool" ascii wide
        $i3   = "OpenPeer" ascii wide
    condition:
        uint16(0) == 0x5a4d and filesize < 4MB and
        ($dll or $ng) and
        ($i1 or $i2 or $i3)
}

rule Neunative_Host_Artifacts_Text
{
    meta:
        author      = "Jarmi"
        description = "Detects scripts/notes/configs referencing Neunative host artifacts (registry, logs, director, relay port)"
        date        = "2026-06-28"
        reference   = "https://github.com/deepfield/public-research/blob/main/reports/2026-06-18-robovpn-neunative.md"
        confidence  = "medium"
        family      = "Neunative/Vo1d-Popa"
    strings:
        $a1 = "HKCU\\Software\\Neunative" ascii nocase
        $a2 = "NeuNative.log" ascii nocase
        $a3 = "logNeunative.txt" ascii nocase
        $a4 = "lb.gmslb.net" ascii nocase
        $a5 = "viki-play.com" ascii nocase
        $a6 = "star-layer.com" ascii nocase
        $a7 = "/regdev?usr=" ascii nocase
    condition:
        filesize < 200KB and
        ($a1 or $a2 or $a3 or $a4 or $a5 or $a6 or $a7)
}
