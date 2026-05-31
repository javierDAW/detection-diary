/*
 * EVMDeFi_NPM_Typosquat_Telemetry_2026
 * Author: Jarmi
 * Date:   2026-05-07
 * Reference:
 *   https://xygeni.io/blog/evm-defi-npm-typosquatting-attack-steals-developer-keys/
 *   https://registry.npmjs.org/viem-core
 *
 * Targets the telemetry.js payload byte-identical across the 6 packages
 * (viem-core, viem-utils-core, hardhat-core-utils, evm-utils,
 *  foundry-utils, web3-utils-core) published 2026-05-06.
 *
 * Anchors:
 *   - SHA-256 known: 71426e93cb6143052d5aeeca920850f8a0343c95bc65aab9a15145848cc5bff1
 *   - Env-var activation gate strings (literal source markers)
 *   - AES-256-GCM creation + crypto.createCipheriv combo
 *   - IPv4 literal 76.13.37.80
 *   - NODE_TLS_REJECT_UNAUTHORIZED=0 disable
 *   - Web3 keystore path globs
 *
 * Confidence: high (when sha256 anchor matches); medium when only string anchors match.
 */

import "hash"

rule EVMDeFi_NPM_Typosquat_Telemetry_KnownHash_2026
{
    meta:
        author      = "Jarmi"
        description = "Known SHA-256 of telemetry.js across 6-package cluster (Xygeni)"
        date        = "2026-05-07"
        reference   = "https://xygeni.io/blog/evm-defi-npm-typosquatting-attack-steals-developer-keys/"
        confidence  = "high"
        family      = "EVMDeFiTypoStealer"
    condition:
        hash.sha256(0, filesize) == "71426e93cb6143052d5aeeca920850f8a0343c95bc65aab9a15145848cc5bff1"
}

rule EVMDeFi_NPM_Typosquat_Telemetry_Heuristic_2026
{
    meta:
        author      = "Jarmi"
        description = "Heuristic anchors of telemetry.js (env gate + AES-256-GCM + IPv4 + TLS reject + dev-secret paths)"
        date        = "2026-05-07"
        reference   = "https://xygeni.io/blog/evm-defi-npm-typosquatting-attack-steals-developer-keys/"
        confidence  = "medium"
        family      = "EVMDeFiTypoStealer"

    strings:
        // Env-var activation gate (T1480)
        $g_alchemy   = "ALCHEMY_API_KEY"
        $g_infura    = "INFURA_KEY"
        $g_pkey      = "PRIVATE_KEY"
        $g_mnemonic  = "MNEMONIC"
        $g_deployer  = "DEPLOYER_KEY"

        // Crypto + TLS-evade combo (T1573.001 + T1027)
        $c_aes       = "aes-256-gcm"
        $c_cipheriv  = "createCipheriv"
        $c_tlsoff_a  = "NODE_TLS_REJECT_UNAUTHORIZED"
        $c_tlsoff_b  = "process.env.NODE_TLS_REJECT_UNAUTHORIZED"

        // Hard-coded C2 (T1071.001)
        $c2          = "76.13.37.80"

        // Dev-secret target paths (T1552.001 / T1555.005)
        $p_aws       = "/.aws/credentials"
        $p_npmrc     = "/.npmrc"
        $p_foundry   = "/.foundry/keystores"
        $p_geth      = "/.ethereum/keystore"
        $p_brownie   = "/.brownie/accounts"

    condition:
        filesize < 32KB and
        // 3 of 5 env triggers
        3 of ($g_*) and
        // crypto + TLS-evade combo
        2 of ($c_aes, $c_cipheriv, $c_tlsoff_a, $c_tlsoff_b) and
        // either the known C2 or 2 dev-secret paths
        ( $c2 or 2 of ($p_*) )
}
