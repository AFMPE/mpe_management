resource "my_alert_rule" "rule_321" {
  name = "Mass secret retrieval from Azure Key Vault"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Low
  query = <<EOF
let EventCountThreshold = 25;
// To avoid any False Positives, filtering using AppId is recommended. For example the AppId 509e4652-da8d-478d-a730-e9d4a1996ca4 has been added in the query as it corresponds 
// to Azure Resource Graph performing VaultGet operations for indexing and syncing all tracked resources across Azure.
let Allowedappid = dynamic(["509e4652-da8d-478d-a730-e9d4a1996ca4"]);
let OperationList = dynamic(
["SecretGet", "KeyGet", "VaultGet"]);
AzureDiagnostics
| where not((identity_claim_appid_g in (Allowedappid)) and OperationName == 'VaultGet')
| extend ResultType = columnifexists("ResultType", "None"), identity_claim_http_schemas_microsoft_com_identity_claims_objectidentifier_g = columnifexists("identity_claim_http_schemas_microsoft_com_identity_claims_objectidentifier_g", "None")
| where ResultType !~ "None" and isnotempty(ResultType)
| where identity_claim_http_schemas_microsoft_com_identity_claims_objectidentifier_g !~ "None" and isnotempty(identity_claim_http_schemas_microsoft_com_identity_claims_objectidentifier_g)
| where ResourceType =~ "VAULTS" and ResultType =~ "Success"
| where OperationName in (OperationList) 
| summarize count() by identity_claim_http_schemas_microsoft_com_identity_claims_objectidentifier_g, OperationName
| where count_ > EventCountThreshold  
| join (
AzureDiagnostics
| where not((identity_claim_appid_g in (Allowedappid)) and OperationName == 'VaultGet')
| extend ResultType = columnifexists("ResultType", "NoResultType")
| extend requestUri_s = columnifexists("requestUri_s", "None"), identity_claim_http_schemas_microsoft_com_identity_claims_objectidentifier_g = columnifexists("identity_claim_http_schemas_microsoft_com_identity_claims_objectidentifier_g", "None")
| extend id_s = columnifexists("id_s", "None"), CallerIPAddress = columnifexists("CallerIPAddress", "None"), clientInfo_s = columnifexists("clientInfo_s", "None")
| where ResultType !~ "None" and isnotempty(ResultType)
| where identity_claim_http_schemas_microsoft_com_identity_claims_objectidentifier_g !~ "None" and isnotempty(identity_claim_http_schemas_microsoft_com_identity_claims_objectidentifier_g)
| where id_s !~ "None" and isnotempty(id_s)
| where CallerIPAddress !~ "None" and isnotempty(CallerIPAddress)
| where clientInfo_s !~ "None" and isnotempty(clientInfo_s)
| where requestUri_s !~ "None" and isnotempty(requestUri_s)
| where OperationName in~ (OperationList)   
) on identity_claim_http_schemas_microsoft_com_identity_claims_objectidentifier_g 
| summarize EventCount=sum(count_), StartTimeUtc=min(TimeGenerated), EndTimeUtc=max(TimeGenerated), TimeTriggered=makelist(TimeGenerated),OperationNameList=make_set(OperationName), RequestURLList=make_set(requestUri_s), CallerIPList = make_set(CallerIPAddress),  CallerIPMax= arg_max(CallerIPAddress,*) by ResourceType, ResultType, Resource, id_s, identity_claim_http_schemas_microsoft_com_identity_claims_objectidentifier_g, clientInfo_s
| extend timestamp = EndTimeUtc, IPCustomEntity = CallerIPMax, AccountCustomEntity = identity_claim_http_schemas_microsoft_com_identity_claims_objectidentifier_g
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
  techniques = ['T1003']
  display_name = Mass secret retrieval from Azure Key Vault
  description = <<EOT
Identifies mass secret retrieval from Azure Key Vault observed by a single user. 
Mass secret retrival crossing a certain threshold is an indication of credential dump operations or mis-configured applications. 
You can tweak the EventCountThreshold based on average count seen in your environment 
and also filter any known sources (IP/Account) and useragent combinations based on historical analysis to further reduce noise
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
