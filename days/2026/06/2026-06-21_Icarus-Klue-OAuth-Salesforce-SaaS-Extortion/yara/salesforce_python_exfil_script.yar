/*
 * YARA rule: Python automation script for Salesforce REST API bulk exfiltration
 * Author: Jarmi
 * Date: 2026-06-21
 * Reference: https://reliaquest.com/blog/threat-spotlight-integration-abused-in-crm-data-theft
 * Confidence: medium — heuristic; matches on structural patterns of the Python automation
 *              observed in the Icarus/Klue campaign. Scripts of this type will be found on
 *              attacker staging systems or in memory during live exploitation.
 * Family: Icarus
 * Description: Matches Python scripts that combine the distinctive fingerprints of the
 *              Salesforce bulk exfiltration automation: python-urllib user-agent string,
 *              sobjects enumeration endpoint, query endpoint, and QueryMore cursor pagination.
 *              This pattern is highly specific to the Icarus tooling and unlikely in legitimate
 *              integration code (which uses the Salesforce SDK or named client libraries).
 */

rule Salesforce_Python_Exfil_Script_Icarus {
    meta:
        author = "Jarmi"
        description = "Python script performing Salesforce REST API bulk exfiltration via sobjects + query + QueryMore (Icarus tooling pattern)"
        date = "2026-06-21"
        reference = "https://reliaquest.com/blog/threat-spotlight-integration-abused-in-crm-data-theft"
        confidence = "medium"
        family = "Icarus"

    strings:
        $ua_urllib = "python-urllib" nocase
        $endpoint_sobjects = "/services/data/v" ascii wide
        $endpoint_sobjects2 = "/sobjects" ascii wide
        $endpoint_query = "/query" ascii wide
        $querymore = "QueryMore" ascii wide nocase
        $refresh_token = "refresh_token" ascii wide nocase
        $bearer_token = "Bearer " ascii wide
        $salesforce_host = ".salesforce.com" ascii wide
        $soql_select = "SELECT " ascii wide nocase
        $import_urllib = "import urllib" ascii wide

    condition:
        filesize < 2MB
        and (
            (
                $ua_urllib
                and $endpoint_sobjects
                and $endpoint_query
                and $salesforce_host
            )
            or (
                $import_urllib
                and $refresh_token
                and $endpoint_query
                and $querymore
            )
            or (
                $bearer_token
                and $endpoint_sobjects2
                and $soql_select
                and $querymore
                and $salesforce_host
            )
        )
}
