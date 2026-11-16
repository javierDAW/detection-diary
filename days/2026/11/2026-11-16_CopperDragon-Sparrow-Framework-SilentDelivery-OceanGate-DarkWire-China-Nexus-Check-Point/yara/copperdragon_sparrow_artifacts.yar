/*
   CopperDragon Sparrow framework (SilentDelivery / OceanGate / DarkWire) - heuristic artefact rules
   Author: Jarmi
   Date: 2026-11-16
   Reference: Check Point Research 2026-11-10 "Not All That Glitters Is Gold: Tracking CopperDragon's
              Sparrow Framework Around the Globe"
              https://research.checkpoint.com/2026/not-all-that-glitters-is-gold-tracking-copperdragons-sparrow-framework-around-the-globe/
              The Hacker News 2026-11-10
              https://thehackernews.com/2026/11/three-china-nexus-espionage-campaigns.html
   Honesty: roughly 40 percent of the Check Point report was read only through a model summary; no
   first-hand sample analysis. Strings are the literals named in the report (C2 URI paths, persistence
   value, firewall rule name, account name and password, keylogger window class, internal Go name,
   plugin entry point, SparrowShell magic) and were NOT verified against samples; some may be encrypted
   or absent in real builds. Not compiled (no yara binary available at authoring time). Low confidence:
   use for retro-hunting and triage, not blocking. Indicators decay; re-packed variants will evade.
   The JS injector is jsjiami-obfuscated, so the plaintext URI strings may only appear after
   de-obfuscation or in proxy / browser cache captures.
   Reference hashes (SHA256, medium confidence, NOT used in conditions):
     adu.exe (CopperAdu)          40880b6fce6f83df4e902cd29d7abb303ffa3f37c429c382f2aaeea34f7be074
     g.exe (CopperLsa)            9fa421adb5c5dac3b2fc1165b0dddd596e82cfd3b08347a91d63f9e88d8718d0
     filst2.exe (CopperList)      1cd0c608418cca80149ef3077e54969f24cd7ef3f22707cb280fa4b378ffa76b
     hha.dll (SparrowDoor loader) d1da8e2389f48d1d1c0e127f3417e3d3e0dbf54691e22d6d0c863d28b9e7a812
     containerd-demo (AnnobinDoor) 46407cc35c48d19c6b1990a03ebdd19321005ce08d5a98acd168fda55a92d946
     xfs_rudp (Reptile-based)     2ea96ea398e9254706ff2761b86302372c149ef090536ad76231e51d7c810a2a
     CertFixer.msi (6 builds)     see iocs.csv
*/

rule CopperDragon_SilentDelivery_JS_Injector_C2_Paths
{
    meta:
        author = "Jarmi"
        description = "Script content (de-obfuscated injected JS, cached page, proxy capture) carrying the SilentDelivery JS C2 paths: /image-check?t= polling, /report-url beacon with window.location.href, /register-ip; or a jsjiami marker together with any of them"
        date = "2026-11-16"
        reference = "https://research.checkpoint.com/2026/not-all-that-glitters-is-gold-tracking-copperdragons-sparrow-framework-around-the-globe/"
        confidence = "low"
        family = "CopperDragon-SilentDelivery-injector"
    strings:
        $p_check = "/image-check?t=" ascii wide
        $p_report = "/report-url" ascii wide
        $p_register = "/register-ip" ascii wide
        $href = "window.location.href" ascii wide
        $jsjiami = "jsjiami" ascii wide nocase
    condition:
        filesize < 3MB and
        (
            ($p_check and ($p_report or $p_register)) or
            ($p_report and $href) or
            ($jsjiami and ($p_check or $p_report or $p_register))
        )
}

rule CopperDragon_Windows_Tooling_Strings
{
    meta:
        author = "Jarmi"
        description = "Windows PE from the CopperDragon toolset: SquadC WindowsUpdateAssist persistence value, CopperAdu admin$ account with Admin@123456 and RasiUwpApp firewall rule, CopperLogger hidden window class kbl"
        date = "2026-11-16"
        reference = "https://research.checkpoint.com/2026/not-all-that-glitters-is-gold-tracking-copperdragons-sparrow-framework-around-the-globe/"
        confidence = "low"
        family = "CopperDragon-SquadC-CopperAdu-CopperLogger"
    strings:
        $squadc_run = "WindowsUpdateAssist" ascii wide
        $adu_fw = "RasiUwpApp" ascii wide
        $adu_user = "admin$" ascii wide
        $adu_pass = "Admin@123456" ascii wide
        $adu_tok = "LocalAccountTokenFilterPolicy" ascii wide
        $kbl = "kbl" ascii wide fullword
        $rawinput = "RegisterRawInputDevices" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and
        (
            $squadc_run or
            $adu_fw or
            ($adu_user and ($adu_pass or $adu_tok)) or
            ($kbl and $rawinput)
        )
}

rule CopperDragon_OceanGate_Linux_AnnobinDoor_SparrowShell
{
    meta:
        author = "Jarmi"
        description = "Linux ELF from the OceanGate cluster: AnnobinDoor Go backdoor internal name annobinagent (UPX-packed builds need unpacking first), or SparrowShell plugin loader artefacts (xmain entry point, magic 0x11223344 little-endian, dlopen, xfs_rudp / aplk names)"
        date = "2026-11-16"
        reference = "https://research.checkpoint.com/2026/not-all-that-glitters-is-gold-tracking-copperdragons-sparrow-framework-around-the-globe/"
        confidence = "low"
        family = "CopperDragon-AnnobinDoor-SparrowShell"
    strings:
        $annobin = "annobinagent" ascii
        $containerd = "containerd-demo" ascii
        $xmain = "xmain" ascii fullword
        $dlopen = "dlopen" ascii
        $magic = { 44 33 22 11 }
        $xfs = "xfs_rudp" ascii
        $aplk = "aplk" ascii fullword
    condition:
        uint32(0) == 0x464C457F and filesize < 20MB and
        (
            $annobin or
            ($containerd and $xmain) or
            ($xmain and $dlopen and $magic) or
            ($xfs and ($aplk or $magic))
        )
}
