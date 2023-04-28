resource "my_alert_rule" "rule_258" {
  name = "Probable AdFind Recon Tool Usage"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = PT1H
  severity = High
  query = <<EOF
let args = dynamic(["objectcategory","domainlist","dcmodes","adinfo","trustdmp","computers_pwdnotreqd","Domain Admins", "objectcategory=person", "objectcategory=computer", "objectcategory=*","dclist"]);
let parentProcesses = dynamic(["pwsh.exe","powershell.exe","cmd.exe"]);
DeviceProcessEvents
//looks for execution from a shell
| where InitiatingProcessFileName in (parentProcesses)
// main filter
| where FileName =~ "AdFind.exe" or SHA256 == "c92c158d7c37fea795114fa6491fe5f145ad2f8c08776b18ae79db811e8e36a3"
   // AdFind common Flags to check for from various threat actor TTPs
    or ProcessCommandLine has_any (args)
| extend AccountCustomEntity = AccountName, HostCustomEntity = DeviceName, ProcessCustomEntity = InitiatingProcessFileName, CommandLineCustomEntity = ProcessCommandLine, AlgorithmCustomEntity = "SHA256", FileHashCustomEntity = SHA256
| where not(FileName has "ldifde.exe")
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = AccountCustomEntity
    }
    entity_type = Host
    field_mappings {
      identifier = HostName
      column_name = HostCustomEntity
    }
    entity_type = Process
    field_mappings {
      identifier = ProcessId
      column_name = ProcessCustomEntity
      identifier = CommandLine
      column_name = CommandLineCustomEntity
    }
    entity_type = FileHash
    field_mappings {
      identifier = Algorithm
      column_name = AlgorithmCustomEntity
      identifier = Value
      column_name = FileHashCustomEntity
    }
  }
  tactics = ['Discovery']
  techniques = ['T1018']
  display_name = Probable AdFind Recon Tool Usage
  description = <<EOT
Identifies the host and account that executed AdFind by hash and filename in addition to common and unique flags that are used by many threat actors in discovery.
EOT
  enabled = True
  create_incident = True
  grouping_configuration {
    enabled = False
    reopen_closed_incident = False
    lookback_duration = P1D
    entity_matching_method = AllEntities
    group_by_entities = []
    group_by_alert_details = None
    group_by_custom_details = None
  }
  suppression_duration = PT5H
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
