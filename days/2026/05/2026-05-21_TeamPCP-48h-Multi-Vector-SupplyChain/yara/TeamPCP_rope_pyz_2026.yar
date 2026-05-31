/*
   TeamPCP_rope_pyz_2026.yar
   YARA rules for the rope.pyz Python zipapp payload distributed by the TeamPCP
   48-hour mega-campaign (StepSecurity + Wiz + Snyk, 2026-05-18/19) plus the
   companion known-hash anchors for the three malicious durabletask wheels.
   The heuristic rule looks for a Python zipapp shape (PK magic + __main__.py)
   combined with multiple TeamPCP IoC anchors and 2+ credential-path anchors.
   Author: Jarmi
*/

import "hash"

rule TeamPCP_rope_pyz_Heuristic_2026
{
    meta:
        author      = "Jarmi"
        description = "Heuristic for rope.pyz TeamPCP zipapp payload from 2026-05-18 mega-campaign"
        date        = "2026-05-21"
        reference   = "https://www.wiz.io/blog/durabletask-teampcp-supply-chain-attack"
        confidence  = "high"
        family      = "rope.pyz / TeamPCP / Mini Shai-Hulud"

    strings:
        // Python zipapp markers
        $zipapp_pk    = { 50 4B 03 04 }
        $zipapp_main  = "__main__.py" ascii

        // TeamPCP shared C2 anchors
        $c2_primary   = "check.git-service.com" ascii nocase
        $c2_secondary = "t.m-kosche.com" ascii nocase
        $c2_legacy_ip = "83.142.209.194" ascii
        $c2_endpoint1 = "/api/public/version" ascii
        $c2_endpoint2 = "/v1/models" ascii
        $c2_endpoint3 = "/audio.mp3" ascii

        // rope.pyz runtime artefacts
        $marker_main  = ".sys-update-check" ascii
        $marker_k8s   = ".sys-update-check-k8s" ascii
        $ssm_state    = "ssm_instances.json" ascii
        $rope_state   = "/tmp/.rope_state" ascii
        $tmp_managed  = "/tmp/managed.pyz" ascii
        $tmp_rope     = "/tmp/rope-" ascii

        // Credential paths (anchors of opportunity)
        $cred_aws     = ".aws/credentials" ascii
        $cred_kube    = ".kube/config" ascii
        $cred_bw      = "bw unlock" ascii nocase
        $cred_op      = "op signin" ascii nocase
        $cred_ssh     = "/.ssh/id_" ascii
        $cred_npmrc   = ".npmrc" ascii
        $cred_pypirc  = ".pypirc" ascii
        $cred_bash    = ".bash_history" ascii
        $cred_zsh     = ".zsh_history" ascii

    condition:
        filesize < 5MB
        and $zipapp_pk at 0
        and $zipapp_main
        and (
                2 of ($c2_primary, $c2_secondary, $c2_legacy_ip, $c2_endpoint1, $c2_endpoint2, $c2_endpoint3)
                or 1 of ($marker_main, $marker_k8s, $ssm_state, $rope_state, $tmp_managed, $tmp_rope)
            )
        and 2 of ($cred_aws, $cred_kube, $cred_bw, $cred_op, $cred_ssh, $cred_npmrc, $cred_pypirc, $cred_bash, $cred_zsh)
}

rule TeamPCP_rope_pyz_Known_Hashes_2026
{
    meta:
        author      = "Jarmi"
        description = "Hash anchors for rope.pyz payload and durabletask malicious wheels"
        date        = "2026-05-21"
        reference   = "https://www.wiz.io/blog/durabletask-teampcp-supply-chain-attack"
        confidence  = "high"
        family      = "rope.pyz / durabletask malicious wheels"

    condition:
        // rope.pyz payload (Wiz)
        hash.sha256(0, filesize) == "069ac1dc7f7649b76bc72a11ac700f373804bfd81dab7e561157b703999f44ce"
        // durabletask-1.4.1-py3-none-any.whl (Wiz)
        or hash.sha256(0, filesize) == "7d80b3ef74ad7992b93c31966962612e4e2ceb93e7727cdbd1d2a9af47d44ba8"
        // durabletask-1.4.2-py3-none-any.whl (Wiz)
        or hash.sha256(0, filesize) == "aeaf583e20347bf850e2fabdcd6f4982996ba023f8c2cd56bbd299cfd56516f5"
        // durabletask-1.4.3-py3-none-any.whl (Wiz)
        or hash.sha256(0, filesize) == "877ff2531a63393c4cb9c3c86908b62d9c4fc3db971bc231c48537faae6cb3ec"
}
