/*
   Joyfill npm supply-chain implant - StepSecurity 2026-07-28.
   Text/JS-artifact rules for the malicious dist bundles and the staged Socket.IO RAT.
   Rule 1 matches the injected loader block (campaign marker + Node primitive stashing +
   the injection sentinel tags written into developer-tool files).
   Rule 2 matches the stage-3 Socket.IO RAT by its command-verb surface and campaign beacon.
   Every declared string is referenced in the condition (repo validator requirement).
   Author: Jarmi
*/

rule Joyfill_npm_Loader_Injected_Block
{
    meta:
        author = "Jarmi"
        description = "Injected on-import loader block from the Joyfill npm compromise (campaign 9-0135-3): stashes require/module under short globals and carries the worm sentinel tags"
        date = "2026-07-30"
        reference = "https://www.stepsecurity.io/blog/joyfill-npm-supply-chain-compromise"
        confidence = "high"
        family = "Joyfill-npm-implant"
    strings:
        $marker  = "9-0135-3" ascii wide
        $req     = "global['r']=require" ascii wide
        $req2    = "global[\"r\"]=require" ascii wide
        $modobj  = "typeof module" ascii wide
        $sent1   = "C250617A" ascii
        $sent2   = "C260512A" ascii
        $sent3   = "RS260605" ascii
    condition:
        filesize < 8MB and
        $marker and
        ($req or $req2) and
        ($modobj or $sent1 or $sent2 or $sent3)
}

rule Joyfill_npm_SocketIO_RAT
{
    meta:
        author = "Jarmi"
        description = "Stage-3 Socket.IO remote access trojan from the Joyfill npm compromise - command verbs, campaign beacon and C2/upload globals"
        date = "2026-07-30"
        reference = "https://www.stepsecurity.io/blog/joyfill-npm-supply-chain-compromise"
        confidence = "high"
        family = "Joyfill-npm-implant"
    strings:
        $v_info  = "ss_info" ascii wide
        $v_eval  = "ss_eval" ascii wide
        $v_upf   = "ss_upf" ascii wide
        $v_inz   = "ss_inz" ascii wide
        $v_cb    = "ss_cb" ascii wide
        $beacon  = "identify" ascii wide
        $sockurl = "_t_s" ascii wide
        $vtag    = "_V" ascii wide
        $ipapi   = "ip-api.com" ascii wide
    condition:
        filesize < 4MB and
        $beacon and $vtag and
        3 of ($v_info, $v_eval, $v_upf, $v_inz, $v_cb) and
        ($sockurl or $ipapi)
}
