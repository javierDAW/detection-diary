rule artoken_phishing_kit_javascript
{
    meta:
        author = "Jarmi"
        description = "Detects the ARToken/EvilTokens-affiliate phishing kit JavaScript bundle via hardcoded operator identifiers and API contract strings documented by Cisco Talos"
        date = "2026-07-22"
        reference = "https://blog.talosintelligence.com/artoken-inside-an-eviltokens-affiliate-panel-targeting-microsoft-365/"
        confidence = "high"
        family = "ARToken (EvilTokens affiliate PhaaS)"

    strings:
        $operator_uuid = "84eb384d-cd3e-4c90-a283-c960ce557913"
        $jwt_key = "artoken_jwt"
        $client_mode = "clientMode\":\"broker\""
        $device_start_api = "/api/device/start"
        $prt_setup = "/prt/setup"
        $prt_cookie = "/prt/cookie"
        $persist_flag = "persistAfterPassChange"

    condition:
        filesize < 5MB and
        ($operator_uuid or $jwt_key or ($client_mode and $device_start_api) or ($prt_setup and $prt_cookie) or $persist_flag)
}
