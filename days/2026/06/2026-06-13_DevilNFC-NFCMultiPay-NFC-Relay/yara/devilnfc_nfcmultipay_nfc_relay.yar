// DevilNFC / NFCMultiPay Android NFC relay families (Cleafy TIR, 2026-05-18).
// These are repo-authored hunting rules anchored on durable string/behavioural
// artifacts (HCE dummy AID, Xposed hook target, NFCGate native lib, MQTT/REST relay
// endpoints), NOT a copy of any vendor signature set. Scan the APK and/or its
// extracted classes.dex / resources (apktool / unzip) — APK strings may be compressed
// inside the zip, so prefer scanning the decoded artifacts for best coverage.
// Reference: https://www.cleafy.com/cleafy-labs/nfc-relay-goes-local-how-ai-is-accelerating-a-new-wave-of-independent-malware-developers

rule MAL_DevilNFC_Reader_APK
{
    meta:
        author = "Jarmi"
        description = "DevilNFC Android NFC relay (dual-role APK: passive reader + HCE tapper)"
        date = "2026-06-13"
        reference = "https://www.cleafy.com/cleafy-labs/nfc-relay-goes-local-how-ai-is-accelerating-a-new-wave-of-independent-malware-developers"
        confidence = "high"
        family = "DevilNFC"
        hash = "caa5e8cf3275339d251210072ebe88c2"
    strings:
        $pkg        = "com.devilnfc.reader" ascii
        $aid_dummy  = "F0010203040506" ascii nocase
        $hook       = "findSelectAid" ascii
        $nfcgate    = "libnfcgate.so" ascii
        $kiosk      = "KioskActivity" ascii
        $exfil      = "api_pin.php" ascii
    condition:
        filesize < 80MB
        and ($pkg
             or ($hook and ($nfcgate or $aid_dummy))
             or ($exfil and $kiosk))
}

rule MAL_NFCMultiPay_Relay_APK
{
    meta:
        author = "Jarmi"
        description = "NFCMultiPay Android NFC relay (pure-Java reader; REST polling / MQTT broker)"
        date = "2026-06-13"
        reference = "https://www.cleafy.com/cleafy-labs/nfc-relay-goes-local-how-ai-is-accelerating-a-new-wave-of-independent-malware-developers"
        confidence = "high"
        family = "NFCMultiPay"
        hash = "35dd9c3a56e88a39bf6c8fdad46b0398"
        hash = "9d19527aeb4cabfb40bbaea6d73b5ff0"
    strings:
        $mqtt_ready = "nfc/relay/" ascii
        $mqtt_card  = "card_ready" ascii
        $rest_pin   = "/api/nfc/check-pin" ascii
        $rest_poll  = "/api/nfc/poll" ascii
        $rest_pub   = "/api/nfc/publish" ascii
    condition:
        filesize < 80MB
        and (($mqtt_ready and $mqtt_card)
             or $rest_pin
             or ($rest_poll and $rest_pub))
}

rule HUNT_NFCGate_Derived_Relay_Core
{
    meta:
        author = "Jarmi"
        description = "Generic NFCGate-derived NFC relay core (PPSE + HostApduService + relay lib); broad hunting rule"
        date = "2026-06-13"
        reference = "https://github.com/nfcgate/nfcgate"
        confidence = "low"
        family = "NFC-Relay-Generic"
    strings:
        $ppse       = "2PAY.SYS.DDF01" ascii
        $ppse_hex   = "325041592E5359532E4444463031" ascii nocase
        $nfcgate    = "nfcgate" ascii nocase
        $hce_meta   = "android.nfc.cardemulation.host_apdu_service" ascii
        $isodep     = "android.nfc.tech.IsoDep" ascii
    condition:
        filesize < 80MB
        and (($ppse or $ppse_hex) and ($nfcgate or $hce_meta))
        or ($nfcgate and $isodep and $hce_meta)
}
