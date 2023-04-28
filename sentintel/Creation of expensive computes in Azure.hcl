resource "my_alert_rule" "rule_213" {
  name = "Creation of expensive computes in Azure"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Low
  query = <<EOF
let tokens = dynamic(["416","208","128","120","96","80","72","64","48","44","40","g5","gs5","g4","gs4","nc12","nc24","nv12"]);
let operationList = dynamic(["microsoft.compute/virtualmachines/write", "microsoft.resources/deployments/write"]);
AzureActivity
| where tolower(OperationNameValue) in (operationList)
| where ActivityStatusValue == "Accepted" 
| where isnotempty(Properties)
| extend vmSize = tolower(tostring(parse_json(tostring(parse_json(tostring(parse_json(tostring(parse_json(Properties).responseBody)).properties)).hardwareProfile)).vmSize))
| where isnotempty(vmSize)
| where vmSize has_any (tokens) 
| extend ComputerName = tostring(parse_json(tostring(parse_json(tostring(parse_json(tostring(parse_json(Properties).responseBody)).properties)).osProfile)).computerName)
| extend clientIpAddress = tostring(parse_json(HTTPRequest).clientIpAddress)
| project TimeGenerated, OperationNameValue, ActivityStatusValue, Caller, CallerIpAddress, ComputerName, vmSize
| extend timestamp = TimeGenerated, AccountCustomEntity = Caller, IPCustomEntity = CallerIpAddress
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
  tactics = ['DefenseEvasion']
  techniques = ['T1578']
  display_name = Creation of expensive computes in Azure
  description = <<EOT
Identifies the creation of large size/expensive VMs (GPU or with large no of virtual CPUs) in Azure.
Adversary may create new or update existing virtual machines sizes to evade defenses 
or use it for cryptomining purposes.
For Windows/Linux Vm Sizes - https://docs.microsoft.com/azure/virtual-machines/windows/sizes 
Azure VM Naming Conventions - https://docs.microsoft.com/azure/virtual-machines/vm-naming-conventions
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
