resource "my_alert_rule" "rule_60" {
  name = "Sensitive Azure Key Vault operations"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Low
  query = <<EOF
let SensitiveOperationList = dynamic(
["VaultDelete", "KeyDelete", "SecretDelete", "SecretPurge", "KeyPurge", "SecretBackup", "KeyBackup"]);
AzureDiagnostics
| extend ResultType = columnifexists("ResultType", "NoResultType")
| extend requestUri_s = columnifexists("requestUri_s", "None"), identity_claim_http_schemas_microsoft_com_identity_claims_objectidentifier_g = columnifexists("identity_claim_http_schemas_microsoft_com_identity_claims_objectidentifier_g", "None")
| extend id_s = columnifexists("id_s", "None"), CallerIPAddress = columnifexists("CallerIPAddress", "None"), clientInfo_s = columnifexists("clientInfo_s", "None")
| where ResultType !~ "None" and isnotempty(ResultType)
| where identity_claim_http_schemas_microsoft_com_identity_claims_objectidentifier_g !~ "None" and isnotempty(identity_claim_http_schemas_microsoft_com_identity_claims_objectidentifier_g)
| where id_s !~ "None" and isnotempty(id_s)
| where CallerIPAddress !~ "None" and isnotempty(CallerIPAddress)
| where clientInfo_s !~ "None" and isnotempty(clientInfo_s)
| where requestUri_s !~ "None" and isnotempty(requestUri_s)
| where ResourceType =~ "VAULTS" and ResultType =~ "Success" 
| where OperationName in~ (SensitiveOperationList)  
| summarize EventCount=count(), StartTimeUtc=min(TimeGenerated), EndTimeUtc=max(TimeGenerated), TimeTriggered=makelist(TimeGenerated),OperationNameList=make_set(OperationName), RequestURLList=make_set(requestUri_s), CallerIPList = make_set(CallerIPAddress),  CallerIPMax= arg_max(CallerIPAddress,*) by ResourceType, ResultType, Resource, id_s, identity_claim_http_schemas_microsoft_com_identity_claims_objectidentifier_g, clientInfo_s
| extend timestamp = StartTimeUtc, IPCustomEntity = CallerIPMax, AccountCustomEntity = identity_claim_http_schemas_microsoft_com_identity_claims_objectidentifier_g
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
  tactics = ['Impact']
  techniques = ['T1485']
  display_name = Sensitive Azure Key Vault operations
  description = <<EOT
Identifies when sensitive Azure Key Vault operations are used. This includes: VaultDelete, KeyDelete, SecretDelete, SecretPurge, KeyPurge, SecretBackup, KeyBackup. 
Any Backup operations should match with expected scheduled backup activity.
EOT
  enabled = True
  create_incident = True
  grouping_configuration {
    enabled = False
    reopen_closed_incident = False
    lookback_duration = P1D
    entity_matching_method = AllEntities
    group_by_entities = []
    group_by_alert_details = []
    group_by_custom_details = []
  }
  suppression_duration = PT5H
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
