resource "my_alert_rule" "rule_41" {
  name = "Azure DevOps Variable Secret Not Secured"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
let keywords = dynamic(["secret", "secrets", "password", "PAT", "passwd", "pswd", "pwd", "cred", "creds", "credentials", "credential", "key"]);
AzureDevOpsAuditing
| where OperationName =~ "Library.VariableGroupModified"
| extend Type = tostring(Data.Type)
| extend VariableGroupId = tostring(Data.VariableGroupId)
| extend VariableGroupName = tostring(Data.VariableGroupName)
| mv-expand Data.Variables
| where VariableGroupName has_any (keywords) or Data_Variables has_any (keywords)
| where Type != "AzureKeyVault"
| where Data_Variables !has "IsSecret"
| extend timestamp = TimeGenerated, AccountCustomEntity = ActorUPN, IPCustomEntity = IpAddress
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = AccountCustomEntity
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPCustomEntity
    }
  }
  tactics = ['CredentialAccess']
  techniques = ['T1552']
  display_name = Azure DevOps Variable Secret Not Secured
  description = <<EOT
Credentials used in the build process may be stored as Azure DevOps variables. To secure these variables they should be stored in KeyVault or marked as Secrets. 
This detection looks for new variables added with names that suggest they are credentials but where they are not set as Secrets or stored in KeyVault.
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
