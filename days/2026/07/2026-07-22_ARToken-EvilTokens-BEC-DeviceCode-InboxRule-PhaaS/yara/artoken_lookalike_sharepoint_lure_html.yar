rule artoken_lookalike_sharepoint_lure_html
{
    meta:
        author = "Jarmi"
        description = "Detects an HTML lure page presenting a genuine vendor SharePoint tenant as anchor text while linking to an attacker-controlled lookalike SharePoint tenant, consistent with the ARToken vendor-impersonation invoice lure"
        date = "2026-07-22"
        reference = "https://blog.talosintelligence.com/artoken-inside-an-eviltokens-affiliate-panel-targeting-microsoft-365/"
        confidence = "medium"
        family = "ARToken (EvilTokens affiliate PhaaS)"

    strings:
        $sp_host = "sharepoint.com" ascii wide
        $invoice_theme1 = "outstanding-invoice" ascii wide nocase
        $invoice_theme2 = "invoices appear to still be outstanding" ascii wide nocase
        $hex_mutation = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-(docviewer|onedrive|adobe2)/ ascii wide

    condition:
        filesize < 2MB and $sp_host and ($invoice_theme1 or $invoice_theme2 or $hex_mutation)
}
