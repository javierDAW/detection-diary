/*
   keyv / cacheable npm worm - third-wave Shai-Hulud (Socket / SafeDep, 2026-08-04).
   Text/script-artifact rules. The Stage-2 bundle (Math_Symbol.js / math_init.js) is a
   ~728 KB Bun bundle with polymorphic basE91-encoded strings, so it is anchored by SHA-256
   in iocs.csv rather than by content here. These two rules target the two readable artifacts:
   the Stage-1 setup.mjs Bun loader and the host-level token-revocation dead-man's-switch
   watcher script. Every declared string is referenced in the condition (repo validator
   requirement); explicit OR is used instead of the 1-of-tuple form.
   Author: Jarmi
*/

rule ShaiHulud_keyv_Bun_Loader_setupmjs
{
    meta:
        author = "Jarmi"
        description = "Stage-1 Bun loader (setup.mjs) from the keyv/cacheable npm worm: fetches a standalone Bun 1.3.13 runtime and executes the Stage-2 payload Math_Symbol.js / math_init.js"
        date = "2026-08-06"
        reference = "https://socket.dev/blog/popular-npm-packages-in-the-keyv-and-cacheable-namespaces-compromised-in-active-supply-chain"
        confidence = "high"
        family = "ShaiHulud-keyv-npm-worm"
    strings:
        $bun_url  = "oven-sh/bun/releases/download" ascii wide
        $bun_tag  = "bun-v" ascii wide
        $ver      = "1.3.13" ascii wide
        $dl_tmp   = "bun-dl-" ascii wide
        $exec     = "execFileSync" ascii wide
        $pay1     = "Math_Symbol.js" ascii wide
        $pay2     = "math_init.js" ascii wide
    condition:
        filesize < 512KB and
        $bun_url and
        ($pay1 or $pay2) and
        ($bun_tag or $ver) and
        ($dl_tmp or $exec)
}

rule ShaiHulud_keyv_DeadMans_Switch_Watcher
{
    meta:
        author = "Jarmi"
        description = "Host-level token-revocation dead-man's switch from the keyv/cacheable npm worm: watcher that polls the GitHub API with a stolen token and, on an HTTP 4xx, evaluates a remote-supplied handler string"
        date = "2026-08-06"
        reference = "https://socket.dev/blog/popular-npm-packages-in-the-keyv-and-cacheable-namespaces-compromised-in-active-supply-chain"
        confidence = "high"
        family = "ShaiHulud-keyv-npm-worm"
    strings:
        $name    = "gh-token-monitor" ascii wide
        $label   = "com.user.gh-token-monitor" ascii wide
        $desc    = "GitHub Token Validity Monitor" ascii wide
        $linger  = "loginctl enable-linger" ascii wide
        $handler = "$HANDLER" ascii wide
        $eval    = "eval" ascii wide
        $status  = "HTTP_STATUS" ascii wide
    condition:
        filesize < 256KB and
        $name and
        ($label or $desc) and
        ($linger or $handler or ($eval and $status))
}
