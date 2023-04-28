resource "my_alert_rule" "rule_328" {
  name = "Unusual Network Connection via RunDLL32"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = Low
  query = <<EOF
DeviceNetworkEvents
| where InitiatingProcessCommandLine has "rundll32.exe"
| extend RemoteIP = trim_start("::ffff:", RemoteIP)
| where not(RemoteIP matches regex @"(^10.)|(^172.1[6-9].)|(^172.2[0-9].)|(^172.3[0-1].)|(^192.168.)|(^127.)")
| project-rename
    Computer=DeviceName,
    Account=InitiatingProcessAccountName,
    CommandLine=InitiatingProcessCommandLine,
    GrandParentProcess=InitiatingProcessParentFileName
| where not(GrandParentProcess has_any ("msiexec.exe", "CompatTelRunner.exe", "Revit.exe"))
| where not(CommandLine has_any ("C:\\windows\\system32\\", "MLCFG32.CPL", "shwebsvc.dll", "printui.dll", "csvrelay32.dll", "RefreshBannedAppsList", "ExecuteScheduledBackup", "debug.log", "C:\\Program Files (x86)\\Belarc\\BelMonitor", "csvrloader32.ocx", "CheckIfLatestHPSAInstalled", "C:\\Program Files\\Microsoft Office", "drvinst.exe", "C:\\Program Files\\Seagull", "coin99ip.dll", "acproxy.dll"))
| where not(RemoteUrl has_any ("updates.logitech.com", "login.microsoftonline.com", "ocsp.digicert.com", "crl.caiso.com"))
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = Name
      column_name = Account
    }
    entity_type = Host
    field_mappings {
      identifier = HostName
      column_name = Computer
    }
    entity_type = Process
    field_mappings {
      identifier = CommandLine
      column_name = GrandParentProcess
    }
  }
  tactics = ['Execution']
  techniques = ['T1129', 'T1559']
  display_name = Unusual Network Connection via RunDLL32
  description = <<EOT
'Identifies unusual instances of rundll32.exe making outbound network connections. This may indicate adversarial activity and may identify malicious DLLs'

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
