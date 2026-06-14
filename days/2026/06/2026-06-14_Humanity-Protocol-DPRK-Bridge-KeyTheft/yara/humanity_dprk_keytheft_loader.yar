// Humanity Protocol $36M bridge takeover (Quantstamp, 8 June 2026).
// NO public malware sample hash was released for this incident. These rules are
// repo-authored BEHAVIOURAL HEURISTICS, not signatures of a recovered sample:
//   - HEUR_Hancom_Signed_Loader matches PEs that carry a Hancom code-signing
//     identity (the stolen/forged Korean cert used as a DPRK trust-abuse marker).
//   - HEUR_Wallet_Keystore_Stealer matches binaries that reference multiple
//     wallet/keystore/seed artifacts typical of crypto key-theft tooling.
// Expect to TUNE before production: Hancom-signed binaries are legitimate in
// Korean-office environments, and security/backup tools reference wallet paths.

rule HEUR_Hancom_Signed_Loader
{
    meta:
        author = "Jarmi"
        description = "Heuristic: PE carrying a Hancom code-signing identity (DPRK trust-abuse marker; Humanity Protocol case)"
        date = "2026-06-14"
        reference = "https://www.cryptotimes.io/2026/06/13/humanity-protocol-36m-hack-phishing-email-dprk-links-revealed/"
        confidence = "medium"
        family = "DPRK-linked-loader-heuristic"
    strings:
        $hancom1 = "Hancom" ascii wide
        $hancom2 = "Hancom Inc" ascii wide
        $hancom3 = "HNC" ascii wide
    condition:
        uint16(0) == 0x5A4D
        and filesize < 30MB
        and ($hancom1 or $hancom2 or $hancom3)
}

rule HEUR_Wallet_Keystore_Stealer
{
    meta:
        author = "Jarmi"
        description = "Heuristic: binary referencing multiple wallet/keystore/seed artifacts (crypto key-theft tooling)"
        date = "2026-06-14"
        reference = "https://www.ccn.com/education/crypto/humanity-protocol-private-key-hack-36m-h-token-crash/"
        confidence = "low"
        family = "crypto-keytheft-heuristic"
    strings:
        $w1 = "keystore" ascii wide
        $w2 = "UTC--" ascii wide
        $w3 = "wallet.dat" ascii wide
        $w4 = "MetaMask" ascii wide
        $w5 = "mnemonic" ascii wide
        $w6 = "Gnosis Safe" ascii wide
        $w7 = "Ledger Live" ascii wide
        $w8 = "privateKey" ascii wide
    condition:
        uint16(0) == 0x5A4D
        and filesize < 30MB
        and (
            ($w1 and $w2) or
            ($w3 and $w4) or
            ($w5 and $w8) or
            ($w4 and $w6) or
            ($w7 and $w2) or
            ($w6 and $w8)
        )
}
