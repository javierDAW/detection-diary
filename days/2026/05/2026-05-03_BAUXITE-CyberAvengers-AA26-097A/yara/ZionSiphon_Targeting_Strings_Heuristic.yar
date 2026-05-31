rule ZionSiphon_Targeting_Strings_Heuristic
{
    meta:
        author       = "Jarmi"
        description  = "Heuristic for ZionSiphon (BAUXITE / CyberAv3ngers) — Israeli desalination target list, broken comparator string, Modbus/CIP API references"
        date         = "2026-05-03"
        reference    = "https://www.cisa.gov/news-events/cybersecurity-advisories/"
        confidence   = "medium (heuristic; comparator broken, likely LLM-assisted code)"
        family       = "ZionSiphon"

    strings:
        // Israeli target hardcoded list
        $tgt1  = "Mekorot" ascii nocase
        $tgt2  = "Sorek" ascii nocase
        $tgt3  = "Hadera" ascii nocase
        $tgt4  = "Ashdod" ascii nocase
        $tgt5  = "Palmachim" ascii nocase
        $tgt6  = "Shafdan" ascii nocase

        // Broken comparator strings (ZionSiphon expects Nqvbdk but supplies "Israel")
        $cmp1  = "Israel" ascii nocase
        $cmp2  = "Nqvbdk" ascii
        $cmp3  = "EncryptDecrypt" ascii nocase

        // ICS-relevant API/protocol fingerprints
        $api1  = "modbus" ascii nocase
        $api2  = "EtherNet/IP" ascii nocase
        $api3  = "CIP" ascii fullword

        // Common Win64 PE markers
        $imp1  = "WinHttp" ascii
        $imp2  = "WinHttpOpen" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 4MB and
        3 of ($tgt*) and
        2 of ($cmp*) and
        any of ($api*) and
        any of ($imp*)
}
