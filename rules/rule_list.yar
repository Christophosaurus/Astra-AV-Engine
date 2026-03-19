// ============================================================
// ASTRA AV Engine — Episode 2: Sample YARA Rules
// rules/malware_generic.yar
//
// These are example rules for educational purposes.
// Pull production rules from:
//   - https://github.com/Yara-Rules/rules
//   - https://github.com/Neo23x0/signature-base
//   - https://bazaar.abuse.ch/export/yara/
// ============================================================

rule Suspicious_PowerShell_Download
{
    meta:
        author      = "ASTRA Labs"
        description = "Detects PowerShell download cradles commonly used in droppers"
        severity    = "high"
        reference   = "https://attack.mitre.org/techniques/T1059/001/"

    strings:
        $ps1 = "DownloadString" ascii wide nocase
        $ps2 = "DownloadFile"   ascii wide nocase
        $ps3 = "IEX"            ascii wide nocase
        $ps4 = "Invoke-Expression" ascii wide nocase
        $ps5 = "WebClient"      ascii wide nocase

    condition:
        2 of ($ps*)
}

rule Suspicious_Process_Injection_APIs
{
    meta:
        author      = "ASTRA Labs"
        description = "Detects imports commonly used in process injection techniques"
        severity    = "high"
        reference   = "https://attack.mitre.org/techniques/T1055/"

    strings:
        $api1 = "VirtualAllocEx"     ascii
        $api2 = "WriteProcessMemory" ascii
        $api3 = "CreateRemoteThread" ascii
        $api4 = "NtCreateThreadEx"   ascii
        $api5 = "RtlCreateUserThread" ascii

    condition:
        2 of ($api*)
}

rule Suspicious_Registry_Persistence
{
    meta:
        author      = "ASTRA Labs"
        description = "Detects strings associated with common registry persistence keys"
        severity    = "medium"
        reference   = "https://attack.mitre.org/techniques/T1547/001/"

    strings:
        $reg1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $reg2 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii wide nocase
        $reg3 = "SYSTEM\\CurrentControlSet\\Services" ascii wide nocase

    condition:
        any of ($reg*)
}

rule Suspicious_Base64_Encoded_PE
{
    meta:
        author      = "ASTRA Labs"
        description = "Detects base64-encoded MZ/PE headers — common in fileless malware loaders"
        severity    = "high"

    strings:
        // "TVqQ" is the base64 encoding of the MZ header (4D5A90)
        $b64_mz1 = "TVqQAA" ascii
        $b64_mz2 = "TVoA"   ascii
        $b64_mz3 = "TVpA"   ascii

    condition:
        any of ($b64_mz*)
}

rule Ransomware_FileExtension_Strings
{
    meta:
        author      = "ASTRA Labs"
        description = "Detects hardcoded file extension lists typical of ransomware targeting"
        severity    = "critical"

    strings:
        $ext1 = ".docx" ascii wide
        $ext2 = ".xlsx" ascii wide
        $ext3 = ".pdf"  ascii wide
        $ext4 = ".jpg"  ascii wide
        $ext5 = ".mp4"  ascii wide
        $ransom1 = "YOUR_FILES_ARE_ENCRYPTED" ascii wide nocase
        $ransom2 = "HOW_TO_DECRYPT"           ascii wide nocase
        $ransom3 = "bitcoin"                   ascii wide nocase

    condition:
        3 of ($ext*) and 1 of ($ransom*)
}

rule wannacry_ransomware
{
    meta:
        author = "Astra"
        description = "This is a rule that tests against strings in WannaCry"
        threat_level = 3
        in_the_wild = false
    strings:
        $a = "C:\\%s\\%s"
        $b = "C:\\%s\\qeriuwjhrf"
        $c = "WNcry@2ol7"
        $d = "msg/m_bulgarian.wnry"
        $e = "WanaCrypt0r"
    condition:
        all of them
}
