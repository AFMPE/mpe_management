resource "my_alert_rule" "rule_225" {
  name = "Execution via Regsvcs_Regasm"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = Medium
  query = <<EOF
let SE = (SecurityEvent
| where Channel == "Security"
| where EventID == "4688"
| where AccountType == "User"
| where Process has_any ("RegSvcs.exe" , "RegAsm.exe") and CommandLine has ".dll"
| extend AccountCustomEntity = Account 
| extend HostCustomEntity = Computer
);
let DPE = (DeviceProcessEvents
| where ProcessCommandLine has_any ("RegSvcs.exe" , "RegAsm.exe") and ProcessCommandLine has ".dll"
| extend AccountCustomEntity = AccountName
| extend HostCustomEntity = DeviceName
| extend CommandLine = ProcessCommandLine
);
SE
| union DPE
| where not(ParentProcessName has_any ("CUACAS_Setup.exe"))
| where not(CommandLine has_any ("Program Files", "Program Files (x86)", "WINDOWS\\CCM", "\\Program Files (x86)\\Kofax\\Capture\\Bin\\", "Program Files\\Commvault", "RAPCOM.DLL", "\\Program Files\\Microsoft Configuration Manager\\", "\\Program Files\\SMS_CCM\\", "\\Program Files\\SMS_SRSRP\\", "\\ProgramData\\Lenovo\\", "C:\\Windows\\CCM", "MUGRemoteServerWrapV4.dll", "\\Realtek\\Audio\\Realtek Audio COM Components\\", "\\Program Files\\2FA\\ONE\\Client", "\\Program Files (x86)\\2FA\\Client\\", "Microsoft Configuration Manager", "windows\\CCM\\Microsoft.ConfigurationManagement.SensorFramework.dll", "Windows\\CCM\\Microsoft.ConfigurationManager.SensorManagedProvider.dll", "Program Files\\Microsoft Configuration Manager\\bin\\x64\\", "Program Files\\SMS_CCM\\", "Program Files\\SMS_SRSRP\\srsserver.dll", "Program Files (x86)\\Calabrio ONE", "Program Files\\LogicMonitor","\\system32\\dolbyaposvc", "TitusUtility.dll", "Global\\MSI0000", "AspenTech.CompositeDoc.dll", "register_urpcdotnetdll.bat", "LICAD_11.1.0.125_SETUP.exe", "AdbCsLayer.dll"))
| where not (InitiatingProcessCommandLine has_any ("\\IBM\\SDP\\eclipse.exe"))
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
    entity_type = Process
    field_mappings {
      identifier = CommandLine
      column_name = CommandLine
    }
  }
  tactics = ['Execution']
  techniques = ['T1569']
  display_name = Execution via Regsvcs/Regasm
  description = <<EOT
'RegSvcs.exe and RegAsm.exe are Windows command line utilities that are used to register .NET Component Object Model (COM) assemblies. Adversaries can use RegSvcs.exe and RegAsm.exe to proxy execution of code through a trusted Windows utility.
https://pentestlab.blog/2017/05/19/applocker-bypass-regasm-and-regsvcs/'

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
