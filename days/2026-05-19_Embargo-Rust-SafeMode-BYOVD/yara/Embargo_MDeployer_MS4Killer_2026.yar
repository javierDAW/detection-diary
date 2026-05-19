/*
   Embargo Ransomware — MDeployer + MS4Killer (Rust toolkit)
   Two rules:
     - Embargo_MDeployer_MS4Killer_Heuristic_2026: durable invariants
       (hardcoded RC4 keys, XOR-encrypted mutex lyric anchor, minifilter
       API imports, log message prefixes, embedded vulnerable driver shape)
       with a filesize cap to avoid scanning oversized blobs.
     - Embargo_MDeployer_MS4Killer_Known_Hashes_2026: exact SHA256 anchors
       for the ESET-published samples.
   Author: Jarmi
   Reference: https://www.welivesecurity.com/en/eset-research/embargo-ransomware-rocknrust/
*/

import "hash"
import "pe"

rule Embargo_MDeployer_MS4Killer_Heuristic_2026
{
    meta:
        description = "Heuristic for Embargo MDeployer/MS4Killer Rust toolkit: hardcoded RC4 keys, minifilter API imports, mutex lyric anchor, MDeployer log prefixes, embedded ITM System probmon.sys shape."
        author = "Jarmi"
        date = "2026-05-19"
        reference = "https://www.welivesecurity.com/en/eset-research/embargo-ransomware-rocknrust/"
        confidence = "high"
        family = "Embargo"

    strings:
        // MDeployer payload RC4 key (hardcoded across observed variants)
        $rc4_mdeployer = "wlQYLoPCil3niI7x8CvR9EtNtL/aeaHrZ23LP3fAsJogVTIzdnZ5Pi09ZVeHFkiB" ascii wide
        // MS4Killer driver-blob RC4 key
        $rc4_ms4killer = "FGFOUDa87c21Vg+cxrr71boU6EG+QC1mwViTciNaTUBuW4gQbcKboN9THK4K35sL" ascii wide
        // MDeployer log prefixes
        $log_dec = "[dec]" ascii
        $log_exec = "[exec]" ascii
        $log_execk = "[execk]" ascii
        $log_kler = "[kler]" ascii
        $log_setsb = "[setsb]" ascii
        // Mutex lyric anchors (newer and older builds)
        $mutex_new = "IntoTheFloodAgainSameOldTrip" ascii wide
        $mutex_old = "LoadUpOnGunsBringYourFriends" ascii wide
        // MS4Killer minifilter API imports / strings
        $api_filterload = "FilterLoad" ascii
        $api_fltconnect = "FilterConnectCommunicationPort" ascii
        $api_fltsend = "FilterSendMessage" ascii
        $api_seloaddrv = "SeLoadDriverPrivilege" ascii
        // Service names rotated for the same probmon.sys blob
        $svc_sysprox = "Sysprox" ascii wide
        $svc_proxmon = "Proxmon" ascii wide
        $svc_sysmon64 = "Sysmon64" ascii wide
        // Persistence service name used in Safe Mode
        $svc_irnagentd = "irnagentd" ascii wide
        // ESET-renamed payload filenames
        $file_praxis = "praxisbackup" ascii wide
        $file_acache = "a.cache" ascii wide
        $file_bcache = "b.cache" ascii wide
        // Rust-Embargo specific decoy in MS4Killer process list
        $decoy_firefox = "firefox.exe" ascii
        // ITM System signer string (for samples that embed it)
        $signer_itm = "ITM System Co." ascii wide

    condition:
        uint16(0) == 0x5A4D
        and filesize < 8MB
        and (
            // MDeployer family: payload RC4 key + at least 2 log prefixes
            ($rc4_mdeployer and 2 of ($log_*))
            or
            // MDeployer Safe Mode variant: persistence service name + setsb log prefix
            ($svc_irnagentd and $log_setsb)
            or
            // MS4Killer family: driver-blob RC4 key + minifilter API + service-name rotation
            ($rc4_ms4killer and 2 of ($api_*) and 1 of ($svc_sysprox, $svc_proxmon, $svc_sysmon64))
            or
            // Embargo ransomware payload: mutex lyric anchor (either lyric) + Rust-typical strings
            (1 of ($mutex_new, $mutex_old) and ($file_acache or $file_bcache or $file_praxis))
            or
            // Cross-component anchor: signer string + minifilter API + decoy process name
            ($signer_itm and 1 of ($api_filterload, $api_fltconnect, $api_fltsend) and $decoy_firefox)
        )
}

rule Embargo_MDeployer_MS4Killer_Known_Hashes_2026
{
    meta:
        description = "Exact SHA1/SHA256 anchors for Embargo MDeployer/MS4Killer/ransomware samples and probmon.sys vulnerable driver published by ESET (Oct 2024)."
        author = "Jarmi"
        date = "2026-05-19"
        reference = "https://www.welivesecurity.com/en/eset-research/embargo-ransomware-rocknrust/"
        confidence = "high"
        family = "Embargo"

    condition:
        // probmon.sys v3.0.0.4 — SHA256 from VirusTotal
        hash.sha256(0, filesize) == "023d722cbbdd04e3db77de7e6e3cfeabcef21ba5b2f04c3f3a33691801dd45eb"
        // MDeployer / MS4Killer / ransomware samples — SHA1 anchors (ESET)
        or hash.sha1(0, filesize) == "a1b98b1fbf69af79e5a3f27aa6256417488cc117"
        or hash.sha1(0, filesize) == "f0a25529b0d0aabce9d72ba46aaf1c78c5b48c31"
        or hash.sha1(0, filesize) == "2ba9bf8dd320990119f42f6f68846d8fb14194d6"
        or hash.sha1(0, filesize) == "888f27dd2269119cf9524474a6a0b559d0d201a1"
        or hash.sha1(0, filesize) == "ba14c43031411240a0836bedf8c8692b54698e05"
        or hash.sha1(0, filesize) == "8a85c1399a0e404c8285a723c4214942a45bbff9"
        or hash.sha1(0, filesize) == "612ec1d41b2aa2518363b18381fd89c12315100f"
        or hash.sha1(0, filesize) == "7310d6399683ba3eb2f695a2071e0e45891d743b"
}
