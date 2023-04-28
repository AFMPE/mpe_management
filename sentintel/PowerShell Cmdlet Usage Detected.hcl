resource "my_alert_rule" "rule_381" {
  name = "PowerShell Cmdlet Usage Detected"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = Low
  query = <<EOF
let pscommands = dynamic ([
"Add-NetUser",
"Add-ObjectAcl",
"Add-Persistence",
"Add-ServiceDacl",
"Convert-NameToSid",
"Convert-NT4toCanonical",
"Convert-SidToName",
"Copy-ClonedFile",
"Find-AVSignature",
"Find-ComputerField",
"Find-ForeignGroup",
"Find-ForeignUser",
"Find-GPOComputerAdmin",
"Find-GPOLocation",
"Find-InterestingFile",
"Find-LocalAdminAccess",
"Find-PathDLLHijack",
"Find-ProcessDLLHijack",
"Find-ManagedSecurityGroups",
"Find-UserField",
"Get-ADObject",
"Get-ApplicationHost",
"Get-CachedRDPConnection",
"Get-ComputerDetails",
"Get-ComputerProperty",
"Get-CurrentUserTokenGroupSid",
"Get-DFSshare",
"Get-DomainPolicy",
"Get-ExploitableSystem",
"Get-GPPPassword",
"Get-HttpStatus",
"Get-Keystrokes",
"Get-LastLoggedOn",
"Get-ModifiablePath",
"Get-ModifiableRegistryAutoRun",
"Get-ModifiableScheduledTaskFile",
"Get-ModifiableService",
"Get-ModifiableServiceFile",
"Get-NetComputer",
"Get-NetDomain",
"Get-NetDomainController",
"Get-NetDomainTrust",
"Get-NetFileServer",
"Get-NetForest",
"Get-NetForestCatalog",
"Get-NetForestDomain",
"Get-NetForestTrust",
"Get-NetGPO",
"Get-NetGPOGroup",
"Get-NetGroup",
"Get-NetGroupMember",
"Get-NetLocalGroup",
"Get-NetLoggedon",
"Get-NetOU",
"Get-NetProcess",
"Get-NetRDPSession",
"Get-NetSession",
"Get-NetShare",
"Get-NetSite",
"Get-NetSubnet",
"Get-NetUser",
"Get-ObjectAcl",
"Get-PathAcl",
"Get-Proxy",
"Get-RegistryAlwaysInstallElevated",
"Get-RegistryAutoLogon",
"Get-SecurityPackages",
"Get-ServiceDetail",
"Get-ServiceUnquoted",
"Get-SiteListPassword",
"Get-System",
"Get-TimedScreenshot",
"Get-UnattendedInstallFile",
"Get-UserEvent",
"Get-UserProperty",
"Get-VaultCredential",
"Get-VolumeShadowCopy",
"Get-Webconfig",
"Install-ServiceBinary",
"Install-SSP",
"Invoke-ACLScanner",
"Invoke-AllChecks",
"Invoke-CheckLocalAdminAccess",
"Invoke-CredentialInjection",
"Invoke-DllInjection",
"Invoke-EnumerateLocalAdmin",
"Invoke-EventHunter",
"Invoke-FileFinder",
"Invoke-MapDomainTrust",
"Invoke-Mimikatz",
"Invoke-NinjaCopy",
"Invoke-Portscan",
"Invoke-ProcessHunter",
"Invoke-ReflectivePEInjection",
"Invoke-ReverseDnsLookup",
"Invoke-ServiceAbuse",
"Invoke-ShareFinder",
"Invoke-Shellcode",
"Invoke-TokenManipulation",
"Invoke-UserHunter",
"Invoke-WmiCommand",
"Mount-VolumeShadowCopy",
"New-ElevatedPersistenceOption",
"New-UserPersistenceOption",
"New-VolumeShadowCopy",
"Out-CompressedDll","Out-EncodedCommand",
"Out-EncryptedScript",
"Out-Minidump",
"Remove-Comments",
"Remove-VolumeShadowCopy",
"Restore-ServiceBinary",
"Set-ADObject",
"Set-CriticalProcess",
"Set-MacAttribute",
"Set-MasterBootRecord",
"Set-ServiceBinPath",
"Test-ServiceDaclPermission",
"Write-HijackDll",
"Write-ServiceBinary",
"Write-UserAddMSI"]);
SecurityEvent
| where EventID == "4688"
| where CommandLine has_any (pscommands)
| extend AccountCustomEntity = Account
| extend HostCustomEntity = Computer 
| extend IPCustomEntity = IpAddress

EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = AccountCustomEntity
    }
    entity_type = Host
    field_mappings {
      identifier = FullName
      column_name = HostCustomEntity
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPCustomEntity
    }
  }
  tactics = ['Execution', 'DefenseEvasion']
  techniques = ['T1059']
  display_name = PowerShell Cmdlet Usage Detected
  description = <<EOT
'Identifies when PowerSploit cmdlets are being executed via the commandline.'

EOT
  enabled = True
  create_incident = True
  grouping_configuration {
    enabled = True
    reopen_closed_incident = False
    lookback_duration = PT5H
    entity_matching_method = AllEntities
    group_by_entities = []
    group_by_alert_details = []
    group_by_custom_details = []
  }
  suppression_duration = PT5M
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
