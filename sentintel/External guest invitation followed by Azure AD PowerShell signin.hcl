resource "my_alert_rule" "rule_77" {
  name = "External guest invitation followed by Azure AD PowerShell signin"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = P1D
  severity = Medium
  query = <<EOF
let queryfrequency = 1h;
let queryperiod = 1d;
AuditLogs
| where TimeGenerated > ago(queryperiod)
| where OperationName in ("Invite external user", "Bulk invite users - started (bulk)", "Invite external user with reset invitation status")
| extend InitiatedBy = iff(isnotempty(InitiatedBy.user.userPrincipalName), InitiatedBy.user.userPrincipalName, InitiatedBy.app.displayName)
// Uncomment the following line to filter events where the inviting user was a guest user
//| where InitiatedBy has_any ("live.com#", "#EXT#")
| extend InvitedUser = TargetResources[0].userPrincipalName
| mv-expand UserToCompare = pack_array(InitiatedBy, InvitedUser) to typeof(string)
| where UserToCompare has_any ("live.com#", "#EXT#")
| extend
    parsedUser = replace_string(tolower(iff(UserToCompare startswith "live.com#", tostring(split(UserToCompare, "#")[1]), tostring(split(UserToCompare, "#EXT#")[0]))), "@", "_"),
    InvitationTime = TimeGenerated
| join (
    (union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs)
    | where TimeGenerated > ago(queryfrequency)
    | where UserType != "Member"
    | where AppId has_any                       // This web may contain a list of these apps: https://msshells.net/
        ("1b730954-1685-4b74-9bfd-dac224a7b894",// Azure Active Directory PowerShell
         "04b07795-8ddb-461a-bbee-02f9e1bf7b46",// Microsoft Azure CLI
         "1950a258-227b-4e31-a9cf-717495945fc2",// Microsoft Azure PowerShell
         "a0c73c16-a7e3-4564-9a95-2bdf47383716",// Microsoft Exchange Online Remote PowerShell
         "fb78d390-0c51-40cd-8e17-fdbfab77341b",// Microsoft Exchange REST API Based Powershell
         "d1ddf0e4-d672-4dae-b554-9d5bdfd93547",// Microsoft Intune PowerShell
         "9bc3ab49-b65d-410a-85ad-de819febfddc",// Microsoft SharePoint Online Management Shell
         "12128f48-ec9e-42f0-b203-ea49fb6af367",// MS Teams Powershell Cmdlets
         "23d8f6bd-1eb0-4cc2-a08c-7bf525c67bcd",// Power BI PowerShell
         "31359c7f-bd7e-475c-86db-fdb8c937548e",// PnP Management Shell
         "90f610bf-206d-4950-b61d-37fa6fd1b224",// Aadrm Admin Powershell
         "14d82eec-204b-4c2f-b7e8-296a70dab67e" // Microsoft Graph PowerShell
        )
    | summarize arg_min(TimeGenerated, *) by UserPrincipalName
    | extend
        parsedUser = replace_string(UserPrincipalName, "@", "_"),
        SigninTime = TimeGenerated
    )
    on parsedUser
| project InvitationTime, InitiatedBy, OperationName, InvitedUser, SigninTime, SigninCategory = Category1, SigninUserPrincipalName = UserPrincipalName, IPAddress, AppDisplayName, ResourceDisplayName, UserAgent, InvitationAdditionalDetails = AdditionalDetails, InvitationTargetResources = TargetResources
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = InvitedUser
    }
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = InitiatedBy
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPAddress
    }
  }
  tactics = ['InitialAccess', 'Persistence', 'Discovery']
  techniques = ['T1078', 'T1136', 'T1087']
  display_name = External guest invitation followed by Azure AD PowerShell signin
  description = <<EOT
By default guests have capability to invite more external guest users, guests also can do suspicious Azure AD enumeration. This detection look at guests
users, who have been invited or have invited recently, who also are logging via various PowerShell CLI.
Ref : 'https://danielchronlund.com/2021/11/18/scary-azure-ad-tenant-enumeration-using-regular-b2b-guest-accounts/
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
