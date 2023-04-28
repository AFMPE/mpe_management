resource "my_alert_rule" "rule_165" {
  name = "Call Pwsh From Cmd"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = PT1H
  severity = Medium
  query = <<EOF
union(SecurityEvent 
| where AccountType == "User"
| where Channel == "Security"
| where ParentProcessName has "cmd.exe"
| where Process has "powershell.exe"
| where CommandLine <> ""
| extend AccountCustomEntity = Account, HostCustomEntity = Computer
),(DeviceProcessEvents
| where InitiatingProcessFileName has "cmd.exe"
| where ProcessCommandLine has "powershell"
| extend AccountCustomEntity = AccountName, HostCustomEntity = DeviceName, CommandLine = ProcessCommandLine
)
| where not (InitiatingProcessCommandLine has_any ("Microsoft Defender for Endpoint", "About to call InstallELAMCertificateInfo on handle", "SWSetup", "\\Packages\\Plugins\\Microsoft.Azure.AzureDefenderForServers.MDE.Windows", "\\Packages\\Plugins\\Microsoft.Azure.Monitoring.DependencyAgent.DependencyAgentWindows\\", "GetMARSVersion.ps1", "GetMARSHealth.ps1", "Microsoft.Azure.AzureDefenderForServers", "SMSTSPostUpgrade", "Defender\\MDEClientAnalyzer\\MDEClientAnalyzer.cmd", "ProgramData\\dell\\drivers", "source\\repos\\SSI","Qualys.QualysAgent", "nessus", "WindowsDefenderATPOnboardingScript.cmd"))
| where not (InitiatingProcessParentFileName has_any ("WindowsAzureGuestAgent.exe", "wa_3rd_party_host_64.exe", "Ccm32BitLauncher.exe", "RadeonSettings.exe", "RadeonSoftware.exe", "Microsoft.Management.Services.IntuneWindowsAgent.exe", "ndtrack.exe", "ccSvcHst.exe", "GrammarlyForWindows.exe", "LTSVC.exe", "SecureConnector.exe", "fsprocsvc.exe", "gc_service.exe", "AUEPMaster.exe", "PanGpHip.exe", "InstallCmdWrapper.exe", "ir_agent.exe", "GlnAgentService.exe", "PDQDeployRunner", "source\\repos\\SSI", "Code.exe", "winrshost", "dsa.exe", "hpqams.exe", "RunCommandExtension.exe", "AMDPPMSettings.exe", "AutoUpdateAgent.exe", "balenaEtcher.exe"))
| where not (CommandLine has_any ("C:\\Scheduled Tasks\\Operations\\HFMPRE_ForceStart.ps1", "C:\\Scheduled Tasks\\Operations\\HFM_ForceStart.ps1", 'Microsoft Corporation UEFI CA 2011', "[environment]::OsVersion.Version", "Microsoft Azure Recovery Services Agent\\bin", "hyperv_first_boot.ps1", "cug_imports\\updateUpload-1.ps1", "get-scalemonitor", "VMNetworkAdapterInstances.txt", "dell", "VMSwitchID.txt", "Windows Defender", "powershell", "MdeExtensionHandler.ps1", "(Test-NetConnection).PingSucceeded", "Onboarding", "SecureConnector.exe", "EnableProxy.ps1", "Get-Date", "zscaler", "nessus", "Microsoft.VisualStudio.DevShell.dll", "version.txt", "C:\\ProgramData\\dell\\drivers", "esdFilePath", "\\RebootCheck\\Reboot_Display.ps1", "get-VMNetworkAdapter", "Start-WindowsClientAssessment", "HPQ6001", "Microsoft-Windows-Windows Defender", "Program Files\\HP", "Calabrio ONE", "Microsoft.Azure.AzureDefenderForServers"))
| where not (CommandLine contains "SQBtAHAAbwByAHQALQBNAG8AZAB1AGwAZQA" or CommandLine contains "JABQAHIAbwBnAHIAZQBzAHMAUAByAGUAZgBlAHIAZQBuAGMAZQA9ACIAUwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZ")
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = Name
      column_name = AccountCustomEntity
    }
    entity_type = Host
    field_mappings {
      identifier = HostName
      column_name = HostCustomEntity
    }
  }
  tactics = ['Execution']
  techniques = ['T1059']
  display_name = Call Pwsh From Cmd
  description = <<EOT
'Calling Powershell from Cmd, Sometimes adversaries will call powershell commands from a regular command prompt. This is often never done by 
System Administrators as they would just opt to run powershell rather than cmd. But when using custom built tools cmd will be the main option of choice.'

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
