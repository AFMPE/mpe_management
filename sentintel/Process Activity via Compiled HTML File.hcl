resource "my_alert_rule" "rule_204" {
  name = "Process Activity via Compiled HTML File"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = Low
  query = <<EOF
let SE = (SecurityEvent
    | where EventID == 4688 and Process == "hh.exe"
    | extend AccountCustomEntity = Account, HostCustomEntity = Computer
    );
let DPE = (DeviceProcessEvents
    | where ProcessCommandLine has "hh.exe" 
    | extend
        AccountCustomEntity = AccountUpn,
        HostCustomEntity = DeviceName,
        CommandLine = ProcessCommandLine
    );
SE
| union DPE
| where not(CommandLine has_any ("Program Files (x86)\\Hyland\\Unity Client\\Help Files\\UnityClient.chm", "On-Line-X12.chm", "Program Files\\WinMagic", "UserGuide.chm", "Sage Software", "genetec", "Bentley\\OpenBridge Designer CE 10.10.20", "Bluebeam Software", "\\CUES\\GraniteNet 5.4\\", "\\KG-TOWER Software v 5.4\\", "PWDeliverablesManagementHelp.chm", "Python397.chm", "WZCLINE.chm", "ArcInfoMain.chm", "arwrdsig.chm", "InfoWorksICM.chm", "RISALicensing.chm", "QRSS.chm", "atv6xxprog.chm", "Locator.chm", "SAG10", "AASHTOWare", "ProjectWise", "DDesignWebAPIHelp.chm", "Bulk Rename Utility.chm", "ol-help.chm", "welcome.htm", "C:\\Program Files"))
| where not(InitiatingProcessFolderPath has_any ("sage software"))
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
  }
  tactics = ['Execution', 'DefenseEvasion']
  techniques = ['T1218']
  display_name = Process Activity via Compiled HTML File
  description = <<EOT
'Compiled HTML files (.chm) are commonly distributed as part of the Microsoft HTML Help system. Adversaries may conceal malicious code in a CHM file and deliver it to a victim for execution. CHM content is loaded by the HTML Help executable program (hh.exe).'

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
