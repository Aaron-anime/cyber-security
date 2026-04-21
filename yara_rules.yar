/*
  Starter YARA rules for sandbox triage.
  These are intentionally simple and should be tuned for your environment.
*/

rule Suspicious_PowerShell_EncodedCommand
{
  meta:
    description = "Detects common encoded PowerShell command patterns"
    author = "Cyber Shield Lab"
    severity = "medium"

  strings:
    $s1 = "powershell" nocase ascii wide
    $s2 = "-enc" nocase ascii wide
    $s3 = "FromBase64String" nocase ascii wide

  condition:
    1 of ($s1, $s2, $s3)
}

rule Suspicious_Lolbin_Download
{
  meta:
    description = "Detects common LOLBIN download/execute strings"
    author = "Cyber Shield Lab"
    severity = "high"

  strings:
    $u1 = "certutil -urlcache" nocase ascii wide
    $u2 = "bitsadmin /transfer" nocase ascii wide
    $u3 = "mshta http" nocase ascii wide
    $u4 = "regsvr32 /s /n /u /i:http" nocase ascii wide

  condition:
    any of ($u*)
}

rule Suspicious_Ransomware_Behavior_Strings
{
  meta:
    description = "Detects strings commonly associated with ransomware behavior"
    author = "Cyber Shield Lab"
    severity = "high"

  strings:
    $r1 = "vssadmin delete shadows" nocase ascii wide
    $r2 = "wbadmin delete catalog" nocase ascii wide
    $r3 = "bcdedit /set {default} recoveryenabled no" nocase ascii wide

  condition:
    any of ($r*)
}
