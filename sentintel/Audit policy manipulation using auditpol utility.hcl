resource "my_alert_rule" "rule_43" {
  name = "Audit policy manipulation using auditpol utility"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
let timeframe = 1d;
let AccountAllowList = dynamic(['SYSTEM']);
let SubCategoryList = dynamic(["Logoff", "Account Lockout", "User Account Management", "Authorization Policy Change"]); // Add any Category in the list to be allowed or disallowed
let tokens = dynamic(["clear", "remove", "success:disable","failure:disable"]); 
(union isfuzzy=true
(
SecurityEvent
| where TimeGenerated >= ago(timeframe)
//| where Process =~ "auditpol.exe" 
| where CommandLine has_any (tokens)
| where AccountType !~ "Machine" and Account !in~ (AccountAllowList)
| parse CommandLine with * "/subcategory:" subcategorytoken
| extend SubCategory = tostring(split(subcategorytoken, "\"")[1]) , Toggle =  tostring(split(subcategorytoken, "\"")[2])
| where SubCategory in~ (SubCategoryList) //use in~ for inclusion or !in~ for exclusion
| where Toggle !in~ ("/failure:disable", " /success:enable /failure:disable") // use this filter if required to exclude certain toggles
| project TimeGenerated, Computer, Account, SubjectDomainName,  SubjectUserName, Process, ParentProcessName,  CommandLine, SubCategory, Toggle
| extend timestamp = TimeGenerated, AccountCustomEntity = Account, HostCustomEntity = Computer
),
(
DeviceProcessEvents
| where TimeGenerated >= ago(timeframe)
// | where InitiatingProcessFileName =~ "auditpol.exe" 
| where InitiatingProcessCommandLine has_any (tokens)
| where AccountName !in~ (AccountAllowList)
| parse InitiatingProcessCommandLine with * "/subcategory:" subcategorytoken
| extend SubCategory = tostring(split(subcategorytoken, "\"")[1]) , Toggle =  tostring(split(subcategorytoken, "\"")[2])
| where SubCategory in~ (SubCategoryList) //use in~ for inclusion or !in~ for exclusion
| where Toggle !in~ ("/failure:disable", " /success:enable /failure:disable") // use this filter if required to exclude certain toggles
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessAccountDomain, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName,  InitiatingProcessCommandLine, SubCategory, Toggle
| extend timestamp = TimeGenerated, AccountCustomEntity = AccountName, HostCustomEntity = DeviceName
),
(
Event
| where TimeGenerated > ago(timeframe)
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| extend EventData = parse_xml(EventData).DataItem.EventData.Data
| mv-expand bagexpansion=array EventData
| evaluate bag_unpack(EventData)
| extend Key=tostring(['@Name']), Value=['#text']
| evaluate pivot(Key, any(Value), TimeGenerated, Source, EventLog, Computer, EventLevel, EventLevelName, EventID, UserName, RenderedDescription, MG, ManagementGroupName, Type, _ResourceId)
// | where OriginalFileName =~ "auditpol.exe"
| where CommandLine has_any (tokens)
| where User !in~ (AccountAllowList)
| parse CommandLine with * "/subcategory:" subcategorytoken
| extend SubCategory = tostring(split(subcategorytoken, "\"")[1]) , Toggle =  tostring(split(subcategorytoken, "\"")[2])
| where SubCategory in~ (SubCategoryList) //use in~ for inclusion or !in~ for exclusion
| where Toggle !in~ ("/failure:disable", " /success:enable /failure:disable") // use this filter if required to exclude certain toggles
| project TimeGenerated, Computer, User, Process, ParentImage,  CommandLine, SubCategory, Toggle
| extend timestamp = TimeGenerated, AccountCustomEntity = User, HostCustomEntity = Computer
)
)
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
  tactics = ['Execution']
  techniques = ['T1204']
  display_name = Audit policy manipulation using auditpol utility
  description = <<EOT
This detects attempt to manipulate audit policies using auditpol command.
This technique was seen in relation to Solorigate attack but the results can indicate potential  malicious activity used in different attacks.
The process name in each data source is commented out as an adversary could rename it. It is advisable to keep process name commented but 
if the results show unrelated false positives, users may want to uncomment it.
Refer to auditpol syntax: https://docs.microsoft.com/windows-server/administration/windows-commands/auditpol  
Refer to our M365 blog for details on use during the Solorigate attack:
https://www.microsoft.com/security/blog/2021/01/20/deep-dive-into-the-solorigate-second-stage-activation-from-sunburst-to-teardrop-and-raindrop/
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
