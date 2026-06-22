/*
 * YARA rules for ProSpy Android spyware (Kotlin)
 * Attributed to BITTER APT-linked hack-for-hire operation targeting MENA civil society
 *
 * Author: Jarmi
 * Date: 2026-06-22
 * Reference: https://www.lookout.com/threat-intelligence/article/bitter-hack-for-hire
 * Confidence: high
 * Family: ProSpy (also ToSpy -- ESET naming)
 * Platforms: Android (APK / DEX)
 *
 * Notes:
 * - All declared strings are used in condition (validator requires this).
 * - Explicit OR used; no parenthesised tuple shorthand.
 * - Scan against APK (zip) or extracted DEX/classes.dex.
 */

rule prospy_android_c2_endpoints
{
    meta:
        author      = "Jarmi"
        description = "Detects ProSpy Android spyware by known /v3/ C2 endpoint path strings"
        date        = "2026-06-22"
        reference   = "https://www.lookout.com/threat-intelligence/article/bitter-hack-for-hire"
        confidence  = "high"
        family      = "ProSpy"

    strings:
        $v3_gettype   = "/v3/getType" ascii
        $v3_images    = "/v3/images" ascii
        $v3_videos    = "/v3/videos" ascii
        $v3_contacts  = "/v3/contacts" ascii
        $v3_sms       = "/v3/sms" ascii
        $v3_docs      = "/v3/docs" ascii
        $v3_backup    = "/v3/backup" ascii
        $v3_setevent  = "/v3/setEvent" ascii
        $v3_setstatus = "/v3/setStatus" ascii
        $v3_audios    = "/v3/audios" ascii

    condition:
        filesize < 20MB and
        $v3_gettype and
        $v3_contacts and
        $v3_sms and
        ($v3_setevent or $v3_setstatus) and
        ($v3_images or $v3_videos or $v3_docs or $v3_backup or $v3_audios)
}

rule prospy_android_package_names
{
    meta:
        author      = "Jarmi"
        description = "Detects ProSpy APK by known malicious package names used in messaging-app lures"
        date        = "2026-06-22"
        reference   = "https://www.lookout.com/threat-intelligence/article/bitter-hack-for-hire"
        confidence  = "high"
        family      = "ProSpy"

    strings:
        $pkg1 = "com.chatbot.botim" ascii
        $pkg2 = "com.chat.connect" ascii
        $pkg3 = "the.messenger.bot" ascii
        $pkg4 = "al.totok.chat" ascii
        $pkg5 = "org.thoghtcrime.securesms" ascii
        $pkg6 = "ae.totok.chat" ascii
        $pkg7 = "im.thebot.mesenger" ascii

    condition:
        filesize < 20MB and
        ($pkg1 or $pkg2 or $pkg3 or $pkg4 or $pkg5 or $pkg6 or $pkg7)
}

rule prospy_android_worker_classes
{
    meta:
        author      = "Jarmi"
        description = "Detects ProSpy by Kotlin worker class naming matching Lookout RE findings"
        date        = "2026-06-22"
        reference   = "https://www.lookout.com/threat-intelligence/article/bitter-hack-for-hire"
        confidence  = "medium"
        family      = "ProSpy"

    strings:
        $worker_contacts = "ContactsWorker" ascii
        $worker_sms      = "SmsWorker" ascii
        $worker_docs     = "DocWorker" ascii
        $worker_images   = "ImageWorker" ascii
        $worker_backup   = "BackupWorker" ascii
        $worker_newfiles = "NewFilesWorker" ascii
        $ttkmbackup      = "ttkmbackup" ascii
        $retrofit_okhttp = "okhttp3" ascii

    condition:
        filesize < 20MB and
        $worker_contacts and
        $worker_sms and
        $retrofit_okhttp and
        ($worker_backup or $worker_newfiles or $ttkmbackup) and
        ($worker_docs or $worker_images)
}

rule prospy_android_c2_domains
{
    meta:
        author      = "Jarmi"
        description = "Detects ProSpy C2 domain strings embedded in APK resources or DEX"
        date        = "2026-06-22"
        reference   = "https://www.lookout.com/threat-intelligence/article/bitter-hack-for-hire"
        confidence  = "high"
        family      = "ProSpy"

    strings:
        $c2_1 = "sgnlapp.info" ascii
        $c2_2 = "treasuresland.cc" ascii
        $c2_3 = "relaxmode.org" ascii
        $c2_4 = "track-portal.co" ascii
        $c2_5 = "totokapp.info" ascii
        $c2_6 = "totok-pro.io" ascii
        $c2_7 = "regularsports.org" ascii

    condition:
        filesize < 20MB and
        ($c2_1 or $c2_2 or $c2_3 or $c2_4 or $c2_5 or $c2_6 or $c2_7)
}
