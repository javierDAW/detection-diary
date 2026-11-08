/*
   Poisoned Source (APT29 / Midnight Blizzard) - watering-hole loader, iOS cookie stealer JS and
   Android AndroSnitch payload
   Author: Jarmi
   Date: 2026-11-08
   Reference: Sekoia TDR (2026-11-04) https://www.sekoia.com/blog/poisoned-source-apt29-watering-holes-targets-mobile-devices-with-n-day-exploits
              The Hacker News (2026-11-04) https://thehackernews.com/2026/11/apt29-linked-hackers-hijack-web.html
   Honesty: derived from the Sekoia report (2026-11-04) and THN (2026-11-04); no first-hand sample
   analysis. Strings are the literals quoted by Sekoia; they were not verified against the samples
   and obfuscated or re-packed variants may not contain them.
   Scan targets: web roots, CMS templates and JS libraries of OUR sites, WAF / proxy captures and
   cached content (rule 1); Android device images, MTD-collected files, sandbox drops (rule 2).
   Reference hashes (Sekoia, not used in conditions): AndroSnitch
   387a7fb768db1350a9788d9704e7a72abe07152734e0ff026af72b417e36268c; Class B /v3 stage
   69b6cb327a4d5da99399718f6a66f84de69f89425b0a31f2dcee0682f811596f.
*/

rule APT29_PoisonedSource_Loader_Injection_Or_CookieStealer_JS
{
    meta:
        author = "Jarmi"
        description = "JavaScript containing the Poisoned Source watering-hole loader injection (window.onload + createElement script + temfp.js / campaign hosts) or the iOS Class A cookie-stealer markers (VDGH_TOKEN_REF, ASDhdhashdasads, AHSDhdashashs, only_cookies + deviceUUID)"
        date = "2026-11-08"
        reference = "https://www.sekoia.com/blog/poisoned-source-apt29-watering-holes-targets-mobile-devices-with-n-day-exploits"
        confidence = "medium"
        family = "PoisonedSource-UltimateFingerprinter"
    strings:
        // loader filename and campaign hosts
        $temfp = "5b4c8fea5cbcee273e8d830f52-temfp.js" ascii wide
        $flux = "flux-telemetry.com" ascii wide
        $edge = "edge-ord.clouds-stacks.com" ascii wide
        $starx = "starx-net.com" ascii wide
        // injection snippet building blocks
        $onload = "window.onload" ascii
        $ce1 = "createElement(\"script\")" ascii
        $ce2 = "createElement('script')" ascii
        $plerdy_var = "_0x3af331" ascii
        // Class A cookie stealer markers
        $tok = "VDGH_TOKEN_REF" ascii wide
        $fn1 = "ASDhdhashdasads" ascii
        $fn2 = "AHSDhdashashs" ascii
        $oc = "only_cookies" ascii
        $uuid = "deviceUUID" ascii
    condition:
        filesize < 5MB and
        (
            ($temfp and ($flux or $edge or $plerdy_var)) or
            ($onload and ($ce1 or $ce2) and ($temfp or $flux or $edge)) or
            ($tok and ($fn1 or $fn2)) or
            ($oc and $uuid and ($starx or $tok or $fn1 or $fn2))
        )
}

rule APT29_PoisonedSource_AndroSnitch_ELF
{
    meta:
        author = "Jarmi"
        description = "Android ELF shared object matching the AndroSnitch (libexploit.so) profile: Chrome Cookies / Login Data / History paths, WifiConfigStore.xml paths, Filename / X-Device-Id upload headers and starx-net telemetry endpoint"
        date = "2026-11-08"
        reference = "https://www.sekoia.com/blog/poisoned-source-apt29-watering-holes-targets-mobile-devices-with-n-day-exploits"
        confidence = "medium"
        family = "AndroSnitch"
    strings:
        $lib = "libexploit.so" ascii
        $ck = "/data/data/com.android.chrome/app_chrome/Default/Cookies" ascii
        $ld = "app_chrome/Default/Login Data" ascii
        $hist = "app_chrome/Default/History" ascii
        $wifi1 = "/data/misc/apexdata/com.android.wifi/WifiConfigStore.xml" ascii
        $wifi2 = "/data/misc/apns/0/WifiConfigStore.xml" ascii
        $hdr_dev = "X-Device-Id" ascii
        $hdr_fn = "Filename" ascii
        $c2 = "starx-net" ascii
        $tel = "/telemetry/v12" ascii
        $model = "SM-S938B" ascii
    condition:
        uint32(0) == 0x464c457f and filesize < 20MB and
        (
            ($c2 and ($tel or $hdr_dev)) or
            (($ck or $ld or $hist) and ($wifi1 or $wifi2) and $hdr_dev and $hdr_fn) or
            ($lib and $model and ($ck or $wifi1 or $wifi2))
        )
}
