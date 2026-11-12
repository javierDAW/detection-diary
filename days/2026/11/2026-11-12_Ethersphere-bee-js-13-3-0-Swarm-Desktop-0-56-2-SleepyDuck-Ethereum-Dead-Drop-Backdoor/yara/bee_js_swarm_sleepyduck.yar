/*
   Trojanised @ethersphere/bee-js 13.3.0 and Swarm Desktop 0.56.2 - loader, Go backdoor and persistence artefacts
   (SleepyDuck / EtherDuck-linked Ethereum dead-drop campaign; no named actor)
   Author: Jarmi
   Date: 2026-11-12
   Reference: Socket 2026-11-09; StepSecurity 2026-11-08/09; The Hacker News 2026-11-09;
              GitHub advisory GHSA-hh7j-5m3j-23pf https://github.com/advisories/GHSA-hh7j-5m3j-23pf
   Honesty: rule 1 strings come from the published loader description (header X-Ethersphere, domain
   frameworkmetrics, new Function execution, install log line). Rule 2 strings are static strings
   reported by StepSecurity (not observed executing) plus the Go module name evjawbreaker reported by
   The Hacker News; no sample was available to the author, so byte-level accuracy is NOT verified -
   confidence medium. Rule 3 matches the persistence unit / plist names published by Socket /
   StepSecurity; the unit and plist bodies were not published, so only names and generic structure
   markers are used. Use the published SHA-256 values (see iocs.csv) for exact matching.
*/

rule BeeJs_Swarm_FrameworkMetrics_Loader_JS
{
    meta:
        author = "Jarmi"
        description = "JavaScript loader injected into @ethersphere/bee-js 13.3.0 scripts/generate-version.cjs (postinstall) and Swarm Desktop 0.56.2 dist/desktop/src/index.js: HTTPS request to api.frameworkmetrics.xyz with header X-Ethersphere, response executed via new Function"
        date = "2026-11-12"
        reference = "https://github.com/advisories/GHSA-hh7j-5m3j-23pf"
        confidence = "high"
        family = "SleepyDuck-Linked-Loader"
        hash1 = "ee2f762e9ed3fd89f106e0b80c2e923bf1aed9a280277d3d998a5902c4d9ec0f"
        hash2 = "f81315968e679b48f6bdff1c9b928bb223230d07f44d7948412c2250c2a14deb"
    strings:
        $hdr = "X-Ethersphere" ascii
        $dom = "frameworkmetrics" ascii
        $exec = "new Function" ascii
        $log = "[FrameworkMetrics] analytics v2.3.1 is up to date" ascii
    condition:
        filesize < 10MB and
        $hdr and $dom and
        ($exec or $log)
}

rule SleepyDuck_Linked_Solidity_Go_Backdoor
{
    meta:
        author = "Jarmi"
        description = "Go backdoor dropped to ~/.solidity/ (linux_amd64, linux_arm64, darwin_amd64, darwin_arm64) by the trojanised bee-js / Swarm Desktop payload; hub address read from an Ethereum contract, persistent sh pty shell"
        date = "2026-11-12"
        reference = "https://github.com/advisories/GHSA-hh7j-5m3j-23pf"
        confidence = "medium"
        family = "SleepyDuck-Linked-GoBackdoor"
        hash1 = "9b73e7cd4e1425e770392549d8df46c706139ef476f4f7b9ac405165dc8d9696"
        hash2 = "b601776817363b96295119f7221338a122d5247a35a77a64b04f286e1bbcc565"
        hash3 = "80d2672e2599732d3c0ae2a4cd0d1e3fe4d555a60273ce33feb99db3f34d250f"
        hash4 = "fae61f31f00988fdc5cc9e7272b51e08af2e245d81003237875415930fd27358"
    strings:
        $hub_cmd = "hubclient.runCommand" ascii
        $hub_shell = "hubclient.startShellLocked" ascii
        $pty = "github.com/creack/pty" ascii
        $mod = "evjawbreaker" ascii
        $svc = "solidity-langsupport-runner" ascii
    condition:
        filesize < 40MB and
        (uint32(0) == 0x464c457f or uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe) and
        ($hub_cmd or $hub_shell) and
        ($pty or $mod or $svc)
}

rule SleepyDuck_Linked_Solidity_Persistence_Unit_Or_Plist
{
    meta:
        author = "Jarmi"
        description = "systemd user unit solidity-langsupport-runner.service or LaunchAgent com.solidity.langsupport.runner.plist referencing the ~/.solidity backdoor directory"
        date = "2026-11-12"
        reference = "https://github.com/advisories/GHSA-hh7j-5m3j-23pf"
        confidence = "medium"
        family = "SleepyDuck-Linked-Persistence"
    strings:
        $name_unit = "solidity-langsupport-runner" ascii
        $name_plist = "com.solidity.langsupport.runner" ascii
        $dir = ".solidity" ascii
        $unit_marker = "[Service]" ascii
        $plist_marker = "<plist" ascii
    condition:
        filesize < 20KB and
        uint16(0) != 0x5A4D and
        $dir and
        ($name_unit or $name_plist) and
        ($unit_marker or $plist_marker)
}
