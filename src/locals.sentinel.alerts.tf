# ## The following locals are usd to define the Sentinel Alert rules
locals {
  alert_rules = { 
    "AAD_No_Password_Expiry" = {
    query_frequency      = "P1D"
    query_period         = "P1D"
    severity             = "Low"

    query                = <<EOF
      union isfuzzy=true 
      (
      SecurityEvent
      | where EventID == 4738
      // 2089 value indicates the Don't Expire Password value has been set
      | where UserAccountControl has "%%2089" 
      | extend Value_2089 = iff(UserAccountControl has "%%2089","'Don't Expire Password' - Enabled", "Not Changed")
      // 2050 indicates that the Password Not Required value is NOT set, this often shows up at the same time as a 2089 and is the recommended value.  This value may not be in the event. 
      | extend Value_2050 = iff(UserAccountControl has "%%2050","'Password Not Required' - Disabled", "Not Changed")
      // If value %%2082 is present in the 4738 event, this indicates the account has been configured to logon WITHOUT a password. Generally you should only see this value when an account is created and only in Event 4720: Account Creation Event.  
      | extend Value_2082 = iff(UserAccountControl has "%%2082","'Password Not Required' - Enabled", "Not Changed")
      | project StartTime = TimeGenerated, EventID, Activity, Computer, TargetAccount, TargetSid, AccountType, UserAccountControl, Value_2089, Value_2050, Value_2082, SubjectAccount
      | extend timestamp = StartTime, AccountCustomEntity = TargetAccount, HostCustomEntity = Computer
      ),
      (
      WindowsEvent
      | where EventID == 4738 and EventData has '2089'
      // 2089 value indicates the Don't Expire Password value has been set
      | extend UserAccountControl = tostring(EventData.UserAccountControl)
      | where UserAccountControl has "%%2089" 
      | extend Value_2089 = iff(UserAccountControl has "%%2089","'Don't Expire Password' - Enabled", "Not Changed")
      // 2050 indicates that the Password Not Required value is NOT set, this often shows up at the same time as a 2089 and is the recommended value.  This value may not be in the event. 
      | extend Value_2050 = iff(UserAccountControl has "%%2050","'Password Not Required' - Disabled", "Not Changed")
      // If value %%2082 is present in the 4738 event, this indicates the account has been configured to logon WITHOUT a password. Generally you should only see this value when an account is created and only in Event 4720: Account Creation Event.  
      | extend Value_2082 = iff(UserAccountControl has "%%2082","'Password Not Required' - Enabled", "Not Changed")
      | extend Activity="4738 - A user account was changed."
      | extend TargetAccount = strcat(EventData.TargetDomainName,"\\", EventData.TargetUserName)
      | extend TargetSid = tostring(EventData.TargetSid)
      | extend SubjectAccount = strcat(EventData.SubjectDomainName,"\\", EventData.SubjectUserName)
      | extend SubjectUserSid = tostring(EventData.SubjectUserSid)
      | extend AccountType=case(SubjectAccount endswith "$" or SubjectUserSid in ("S-1-5-18", "S-1-5-19", "S-1-5-20"), "Machine", isempty(SubjectUserSid), "", "User")
      | project StartTime = TimeGenerated, EventID, Activity, Computer, TargetAccount, TargetSid, AccountType, UserAccountControl, Value_2089, Value_2050, Value_2082, SubjectAccount
      | extend timestamp = StartTime, AccountCustomEntity = TargetAccount, HostCustomEntity = Computer
      )
      EOF
    
  
    entity_mappings = [
      {
        entity_type = "Account"
        identifier = "FullName"
        field_name = "AccountCustomEntity"
         
      },
      {
        entity_type = "Host"
        identifier = "HostName"
        field_name = "HostCustomEntity"
          }
          
    ]

    tactics              = ["Persistence"]
    techniques           = ["T1098"]

    display_name = "AAD_No_Password_Expiry"
    description = <<EOT
Identifies whenever a user account has the setting "Password Never Expires" in the user account properties selected.
This is indicated in Security event 4738 in the EventData item labeled UserAccountControl with an included value of %%2089.
%%2089 resolves to "Don't Expire Password - Enabled".
EOT

    enabled = true
    create_incident = true
    grouping_enabled = true
    reopen_closed_incidents = true
    lookback_duration = "P1D"
    entity_matching_method = "AllEntities"
    group_by_entities = []
    group_by_alert_details = ["Severity"]
    suppression_duration = "P1D"
    suppression_enabled  = true
    event_grouping = "SingleAlert"
  }, # End Alert
  
  "User_Added_To_Admin_Grp" = {
    query_frequency      = "P1D"
    query_period         = "P1D"
    severity             = "Medium"

    query                = <<EOF
SecurityEvent
| where EventID == 4728
| where TargetUserName contains "Admin" 
or TargetUserName contains "admin"
| extend AccountCustomEntity = Account 
| extend HostCustomEntity = Computer

EOF
    
  
    entity_mappings = [
      {
        entity_type = "Account"
        identifier = "FullName"
        field_name = "AccountCustomEntity"
         
      },
      {
        entity_type = "Host"
        identifier = "HostName"
        field_name = "HostCustomEntity"
         
      } 
    ]

    tactics              = ["Persistence"]
    techniques           = ["T1098"]

    display_name = "User added to admin group"
    description = <<EOT
'Detects When user is added to a domain group that contains the word admin (Enterprise Admins,Domain Admins,DNS Admins)'

EOT

    enabled = true
    create_incident = true
    grouping_enabled = true
    reopen_closed_incidents = true
    lookback_duration = "P1D"
    entity_matching_method = "AllEntities"
    group_by_entities = []
    group_by_alert_details = ["Severity"]
    suppression_duration = "P1D"
    suppression_enabled  = false
    event_grouping = "SingleAlert"
  }, # End Alert

  "User_Account_Creation" = {
    query_frequency      = "PT1H"
    query_period         = "PT1H"
    severity             = "Low"

    query                = <<EOF
SecurityEvent 
| where EventID == 4688 and (Process == "net.exe" or Process == "net1.exe") and not(ParentProcessName == "net.exe") and (CommandLine contains "user" and CommandLine contains "/add" or CommandLine contains "/ad")
| extend AccountCustomEntity = Account 
| extend HostCustomEntity = Computer

EOF
    
  
    entity_mappings = [
      {
        entity_type = "Account"
        identifier = "Name"
        field_name = "AccountCustomEntity"
         
      },
      {
        entity_type = "Host"
        identifier = "HostName"
        field_name = "HostCustomEntity"
         
      } 
    ]

    tactics              = ["Persistence"]
    techniques           = ["T1098"]

    display_name = "User Account Created"
    description = <<EOT
'Identifies attempts to create new local users. This is sometimes done by attackers to increase access to a system or domain.'

EOT

    enabled = true
    create_incident = true
    grouping_enabled = true
    reopen_closed_incidents = true
    lookback_duration = "PT5H"
    entity_matching_method = "AllEntities"
    group_by_entities = []
    group_by_alert_details = ["Severity"]
    suppression_duration = "PT5H"
    suppression_enabled  = false
    event_grouping = "SingleAlert"
  }, # End Alert

  "User_Account_Added_To_Global_Group" = {
    query_frequency      = "P1D"
    query_period         = "P1D"
    severity             = "Low"

    query                = <<EOF
// For AD SID mappings - https://docs.microsoft.com/windows/security/identity-protection/access-control/active-directory-security-groups
let WellKnownLocalSID = "S-1-5-32-5[0-9][0-9]$";
let WellKnownGroupSID = "S-1-5-21-[0-9]*-[0-9]*-[0-9]*-5[0-9][0-9]$|S-1-5-21-[0-9]*-[0-9]*-[0-9]*-1102$|S-1-5-21-[0-9]*-[0-9]*-[0-9]*-1103$|S-1-5-21-[0-9]*-[0-9]*-[0-9]*-498$|S-1-5-21-[0-9]*-[0-9]*-[0-9]*-1000$";
union isfuzzy=true 
(
SecurityEvent 
// When MemberName contains '-' this indicates addition of a group to a group
| where AccountType == "User" and MemberName != "-"
// 4728 - A member was added to a security-enabled global group
// 4732 - A member was added to a security-enabled local group
// 4756 - A member was added to a security-enabled universal group
| where EventID in (4728, 4732, 4756)   
| where TargetSid matches regex WellKnownLocalSID or TargetSid matches regex WellKnownGroupSID
// Exclude Remote Desktop Users group: S-1-5-32-555
| where TargetSid !in ("S-1-5-32-555")
| extend SimpleMemberName = substring(MemberName, 3, indexof_regex(MemberName, @",OU|,CN") - 3)
| project TimeGenerated, EventID, Activity, Computer, SimpleMemberName, MemberName, MemberSid, TargetUserName, TargetDomainName, TargetSid, UserPrincipalName, SubjectUserName, SubjectUserSid
| extend timestamp = TimeGenerated, AccountCustomEntity = SimpleMemberName, HostCustomEntity = Computer
),
(
WindowsEvent 
// 4728 - A member was added to a security-enabled global group
// 4732 - A member was added to a security-enabled local group
// 4756 - A member was added to a security-enabled universal group
| where EventID in (4728, 4732, 4756)  and  not(EventData has "S-1-5-32-555")
| extend SubjectUserSid = tostring(EventData.SubjectUserSid)
| extend Account =  strcat(tostring(EventData.SubjectDomainName),"\\", tostring(EventData.SubjectUserName))
| extend AccountType=case(Account endswith "$" or SubjectUserSid in ("S-1-5-18", "S-1-5-19", "S-1-5-20"), "Machine", isempty(SubjectUserSid), "", "User")
| extend MemberName = tostring(EventData.MemberName)
// When MemberName contains '-' this indicates addition of a group to a group
| where AccountType == "User" and MemberName != "-"
| extend TargetSid = tostring(EventData.TargetSid)
| where TargetSid matches regex WellKnownLocalSID or TargetSid matches regex WellKnownGroupSID
// Exclude Remote Desktop Users group: S-1-5-32-555
| where TargetSid !in ("S-1-5-32-555")
| extend SimpleMemberName = substring(MemberName, 3, indexof_regex(MemberName, @",OU|,CN") - 3)
| extend MemberSid = tostring(EventData.MemberSid)
| extend TargetUserName = tostring(EventData.TargetUserName)
| extend TargetDomainName = tostring(EventData.TargetDomainName)
| extend UserPrincipalName = tostring(EventData.UserPrincipalName)
| extend SubjectUserName = tostring(EventData.SubjectUserName)
| project TimeGenerated, EventID, Computer, SimpleMemberName, MemberName, MemberSid, TargetUserName, TargetDomainName, TargetSid, UserPrincipalName, SubjectUserName, SubjectUserSid
| extend timestamp = TimeGenerated, AccountCustomEntity = SimpleMemberName, HostCustomEntity = Computer
)
EOF
    
  
    entity_mappings = [
      {
        entity_type = "Account"
        identifier = "Name"
        field_name = "AccountCustomEntity"
         
      },
      {
        entity_type = "Host"
        identifier = "HostName"
        field_name = "HostCustomEntity"
         
      } 
    ]

    tactics              = ["Persistence","PrivilegeEscalation"]
    techniques           = ["T1078","T1098"]

    display_name = "User account added to built in domain local or global group"
    description =  <<EOT
Identifies when a user account has been added to a privileged built in domain local group or global group 
such as the Enterprise Admins, Cert Publishers or DnsAdmins. Be sure to verify this is an expected addition.
EOT

    enabled = true
    create_incident = true
    grouping_enabled = true
    reopen_closed_incidents = true
    lookback_duration = "P1D"
    entity_matching_method = "AllEntities"
    group_by_entities = []
    group_by_alert_details = ["Severity"]
    suppression_duration = "P1D"
    suppression_enabled  = false
    event_grouping = "SingleAlert"
  }, # End Alert

  "User_Account_Created_And_Deleted_Within_10_Minutes" = {
    query_frequency      = "P1D"
    query_period         = "P1D"
    severity             = "Medium"

    query                = <<EOF
let timeframe = 1d;
let spanoftime = 10m;
let threshold = 0;
 (union isfuzzy=true
 (SecurityEvent
| where TimeGenerated > ago(timeframe+spanoftime)
// A user account was created
| where EventID == 4720
| where AccountType =~ "User"
| project creationTime = TimeGenerated, CreateEventID = EventID, CreateActivity = Activity, Computer, TargetUserName, UserPrincipalName, 
AccountUsedToCreate = SubjectAccount, SIDofAccountUsedToCreate = SubjectUserSid, TargetAccount = tolower(TargetAccount), TargetSid
),
(
WindowsEvent
| where TimeGenerated > ago(timeframe+spanoftime)
// A user account was created
| where EventID == 4720
| extend SubjectUserSid = tostring(EventData.SubjectUserSid)
| extend AccountType=case(EventData.SubjectUserName endswith "$" or SubjectUserSid in ("S-1-5-18", "S-1-5-19", "S-1-5-20"), "Machine", isempty(SubjectUserSid), "", "User")
| where AccountType =~ "User"
| extend SubjectAccount = strcat(tostring(EventData.SubjectDomainName),"\\", tostring(EventData.SubjectUserName))
| extend TargetAccount = strcat(EventData.TargetDomainName,"\\", EventData.TargetUserName)
| extend TargetSid = tostring(EventData.TargetSid)
| extend UserPrincipalName = tostring(EventData.UserPrincipalName)
| extend Activity = "4720 - A user account was created."
| extend TargetUserName = tostring(EventData.TargetUserName) 
| project creationTime = TimeGenerated, CreateEventID = EventID, CreateActivity = Activity, Computer, TargetUserName, UserPrincipalName, 
AccountUsedToCreate = SubjectAccount, SIDofAccountUsedToCreate = SubjectUserSid, TargetAccount = tolower(TargetAccount), TargetSid  
))
| join kind= inner (
  (union isfuzzy=true
  (SecurityEvent
  | where TimeGenerated > ago(timeframe)
  // A user account was deleted
  | where EventID == 4726
| where AccountType == "User"
| project deletionTime = TimeGenerated, DeleteEventID = EventID, DeleteActivity = Activity, Computer, TargetUserName, UserPrincipalName, 
AccountUsedToDelete = SubjectAccount, SIDofAccountUsedToDelete = SubjectUserSid, TargetAccount = tolower(TargetAccount), TargetSid
),
(WindowsEvent
| where TimeGenerated > ago(timeframe)
  // A user account was deleted
| where EventID == 4726
| extend SubjectUserSid = tostring(EventData.SubjectUserSid)
| extend SubjectAccount = strcat(tostring(EventData.SubjectDomainName),"\\", tostring(EventData.SubjectUserName))
| extend AccountType=case(SubjectAccount endswith "$" or SubjectUserSid in ("S-1-5-18", "S-1-5-19", "S-1-5-20"), "Machine", isempty(SubjectUserSid), "", "User")
| where AccountType == "User"
| extend TargetSid = tostring(EventData.TargetSid)
| extend UserPrincipalName = tostring(EventData.UserPrincipalName)
| extend Activity = "4726 - A user account was deleted."
| extend TargetUserName = tostring(EventData.TargetUserName) 
| extend TargetAccount = strcat(EventData.TargetDomainName,"\\", EventData.TargetUserName)
| project deletionTime = TimeGenerated, DeleteEventID = EventID, DeleteActivity = Activity, Computer, TargetUserName, UserPrincipalName, AccountUsedToDelete = SubjectAccount, SIDofAccountUsedToDelete = SubjectUserSid, TargetAccount = tolower(TargetAccount), TargetSid))
) on Computer, TargetAccount
| where deletionTime - creationTime < spanoftime
| extend TimeDelta = deletionTime - creationTime
| where tolong(TimeDelta) >= threshold
| project TimeDelta, creationTime, CreateEventID, CreateActivity, Computer, TargetAccount, TargetSid, UserPrincipalName, AccountUsedToCreate, SIDofAccountUsedToCreate,
deletionTime, DeleteEventID, DeleteActivity, AccountUsedToDelete, SIDofAccountUsedToDelete
| extend timestamp = creationTime, AccountCustomEntity = AccountUsedToCreate, HostCustomEntity = Computer
EOF
    
  
    entity_mappings = [
      {
        entity_type = "Account"
        identifier = "Name"
        field_name = "AccountCustomEntity"
         
      },
      {
        entity_type = "Host"
        identifier = "HostName"
        field_name = "HostCustomEntity"
         
      } 
    ]

    tactics              = ["Persistence","PrivilegeEscalation"]
    techniques           = ["T1078","T1098"]

    display_name = "User_Account_Created_And_Deleted_Within_10_Minutes"
    description =  <<EOT
Identifies when a user account is created and then deleted within 10 minutes. This can be an indication of compromise and
an adversary attempting to hide in the noise.
EOT

    enabled = true
    create_incident = true
    grouping_enabled = false
    reopen_closed_incidents = false
    lookback_duration = "P1D"
    entity_matching_method = "AllEntities"
    group_by_entities = []
    group_by_alert_details = ["Severity"]
    suppression_duration = "P1D"
    suppression_enabled  = false
    event_grouping = "SingleAlert"
  }, # End Alert

  "User_Account_Created_And_Disabled_Within_10_Minutes" = {
    query_frequency      = "P1D"
    query_period         = "P1D"
    severity             = "Medium"

    query                = <<EOF
let timeframe = 1d;
let spanoftime = 10m;
let threshold = 0;
SecurityEvent
| where TimeGenerated > ago(timeframe+spanoftime)
// A user account was enabled
| where EventID == 4722
| where AccountType =~ "User"
| where TargetAccount !hassuffix "$"
| project EnableTime = TimeGenerated, EnableEventID = EventID, EnableActivity = Activity, Computer, UserPrincipalName, 
AccountUsedToEnable = SubjectAccount, SIDofAccountUsedToEnable = SubjectUserSid, TargetAccount = tolower(TargetAccount), TargetSid
| join kind= inner (
  SecurityEvent
  | where TimeGenerated > ago(timeframe)
  // A user account was disabled
  | where EventID == 4725
| where AccountType =~ "User"
| project DisableTime = TimeGenerated, DisableEventID = EventID, DisableActivity = Activity, Computer, UserPrincipalName, 
AccountUsedToDisable = SubjectAccount, SIDofAccountUsedToDisable = SubjectUserSid, TargetAccount = tolower(TargetAccount), TargetSid
) on Computer, TargetAccount
| where DisableTime - EnableTime < spanoftime
| extend TimeDelta = DisableTime - EnableTime
| where tolong(TimeDelta) >= threshold
| project TimeDelta, EnableTime, EnableEventID, EnableActivity, Computer, TargetAccount, TargetSid, UserPrincipalName, AccountUsedToEnable, SIDofAccountUsedToEnable, 
DisableTime, DisableEventID, DisableActivity, AccountUsedToDisable, SIDofAccountUsedToDisable
| extend timestamp = EnableTime, AccountCustomEntity = AccountUsedToEnable, HostCustomEntity = Computer
EOF
    
  
    entity_mappings = [
      {
        entity_type = "Account"
        identifier = "Name"
        field_name = "AccountCustomEntity"
         
      },
      {
        entity_type = "Host"
        identifier = "FullName"
        field_name = "HostCustomEntity"
         
      } 
    ]

    tactics              = ["Persistence","PrivilegeEscalation"]
    techniques           = ["T1078","T1098"]

    display_name = "User_Account_Created_And_Disabled_Within_10_Minutes"
    description =  <<EOT
Identifies when a user account is enabled and then disabled within 10 minutes. This can be an indication of compromise and
an adversary attempting to hide in the noise.
EOT

    enabled = true
    create_incident = true
    grouping_enabled = false
    reopen_closed_incidents = false
    lookback_duration = "P1D"
    entity_matching_method = "AllEntities"
    group_by_entities = []
    group_by_alert_details = ["Severity"]
    suppression_duration = "P1D"
    suppression_enabled  = false
    event_grouping = "SingleAlert"
  }, # End Alert

  "User_Account_Was_Locked_O365" = {
    query_frequency      = "PT5H"
    query_period         = "PT5H"
    severity             = "Medium"

    query                = <<EOF
OfficeActivity 
| where Operation == "UserLoginFailed" | where * contains "IdsLocked"
EOF
    
  
    entity_mappings = [
      {
        entity_type = "IP"
        identifier = "Address"
        field_name = "ClientIP"
         
      } 
    ]

    tactics              = ["CredentialAccess"]
    techniques           = ["T1110"]

    display_name = "User_Account_Was_Locked_O365"
    description =  <<EOT
Possible user account brute. Technique: T1110.
EOT

    enabled = true
    create_incident = true
    grouping_enabled = false
    reopen_closed_incidents = false
    lookback_duration = "P1D"
    entity_matching_method = "AllEntities"
    group_by_entities = []
    group_by_alert_details = ["Severity"]
    suppression_duration = "PT5H"
    suppression_enabled  = false
    event_grouping = "SingleAlert"
  }, # End Alert

  "User_Account_Login_CA_Spikes" = {
    query_frequency      = "P1D"
    query_period         = "P1D"
    severity             = "Medium"

    query                = <<EOF
let starttime = 14d;
let timeframe = 1d;
let scorethreshold = 3;
let baselinethreshold = 50;
let aadFunc = (tableName:string){
  // Failed Signins attempts with reasoning related to conditional access policies.
  table(tableName)
  | where TimeGenerated between (startofday(ago(starttime))..startofday(now()))
  | where ResultDescription has_any ("conditional access", "CA") or ResultType in (50005, 50131, 53000, 53001, 53002, 52003, 70044)
  | extend UserPrincipalName = tolower(UserPrincipalName)
  | extend timestamp = TimeGenerated, AccountCustomEntity = UserPrincipalName
};
let aadSignin = aadFunc("SigninLogs");
let aadNonInt = aadFunc("AADNonInteractiveUserSignInLogs");
let allSignins = union isfuzzy=true aadSignin, aadNonInt;
let TimeSeriesAlerts = 
allSignins
| make-series DailyCount=count() on TimeGenerated from startofday(ago(starttime)) to startofday(now()) step 1d by UserPrincipalName
| extend (anomalies, score, baseline) = series_decompose_anomalies(DailyCount, scorethreshold, -1, 'linefit')
| mv-expand DailyCount to typeof(double), TimeGenerated to typeof(datetime), anomalies to typeof(double), score to typeof(double), baseline to typeof(long)
// Filtering low count events per baselinethreshold
| where anomalies > 0 and baseline > baselinethreshold
| extend AnomalyHour = TimeGenerated
| project UserPrincipalName, AnomalyHour, TimeGenerated, DailyCount, baseline, anomalies, score;
// Filter the alerts for specified timeframe
TimeSeriesAlerts
| where TimeGenerated > startofday(ago(timeframe))
| join kind=inner ( 
  allSignins
  | where TimeGenerated > startofday(ago(timeframe))
  // create a new column and round to hour
  | extend DateHour = bin(TimeGenerated, 1h)
  | summarize PartialFailedSignins = count(), LatestAnomalyTime = arg_max(TimeGenerated, *) by bin(TimeGenerated, 1h), OperationName, Category, ResultType, ResultDescription, UserPrincipalName, UserDisplayName, AppDisplayName, ClientAppUsed, IPAddress, ResourceDisplayName
) on UserPrincipalName, $left.AnomalyHour == $right.DateHour
| project LatestAnomalyTime, OperationName, Category, UserPrincipalName, UserDisplayName, ResultType, ResultDescription, AppDisplayName, ClientAppUsed, UserAgent, IPAddress, Location, AuthenticationRequirement, ConditionalAccessStatus, ResourceDisplayName, PartialFailedSignins, TotalFailedSignins = DailyCount, baseline, anomalies, score
| extend timestamp = LatestAnomalyTime, IPCustomEntity = IPAddress, AccountCustomEntity = UserPrincipalName
EOF
    
  
    entity_mappings = [
      {
        entity_type = "Account"
        identifier = "FullName"
        field_name = "AccountCustomEntity"
         
      }
    ]

    tactics              = ["InitialAccess"]
    techniques           = ["T1078"]

    display_name = "User_Account_Login_CA_Spikes"
    description =  <<EOT
 Identifies spike in failed sign-ins from user accounts due to conditional access policied.
Spike is determined based on Time series anomaly which will look at historical baseline values.
Ref : https://docs.microsoft.com/azure/active-directory/fundamentals/security-operations-user-accounts#monitoring-for-failed-unusual-sign-ins
EOT

    enabled = true
    create_incident = true
    grouping_enabled = false
    reopen_closed_incidents = false
    lookback_duration = "P1D"
    entity_matching_method = "AllEntities"
    group_by_entities = []
    group_by_alert_details = ["Severity"]
    suppression_duration = "P1D"
    suppression_enabled  = false
    event_grouping = "SingleAlert"
  }, # End Alert

  "User_Added_To_AAD_Privileged_Groups" = {
    query_frequency      = "PT1H"
    query_period         = "PT1H"
    severity             = "Medium"

    query                = <<EOF
let OperationList = dynamic(["Add member to role","Add member to role in PIM requested (permanent)"]);
let PrivilegedGroups = dynamic(["UserAccountAdmins","PrivilegedRoleAdmins","TenantAdmins"]);
AuditLogs
//| where LoggedByService =~ "Core Directory"
| where Category =~ "RoleManagement"
| where OperationName in~ (OperationList)
| mv-expand TargetResources
| extend modProps = parse_json(TargetResources).modifiedProperties
| mv-expand bagexpansion=array modProps
| evaluate bag_unpack(modProps)
| extend displayName = column_ifexists("displayName", "NotAvailable"), newValue = column_ifexists("newValue", "NotAvailable")
| where displayName =~ "Role.WellKnownObjectName"
| extend DisplayName = displayName, GroupName = replace('"','',newValue)
| extend initByApp = parse_json(InitiatedBy).app, initByUser = parse_json(InitiatedBy).user
| extend AppId = initByApp.appId, 
InitiatedByDisplayName = case(isnotempty(initByApp.displayName), initByApp.displayName, isnotempty(initByUser.displayName), initByUser.displayName, "not available"),
ServicePrincipalId = tostring(initByApp.servicePrincipalId),
ServicePrincipalName = tostring(initByApp.servicePrincipalName),
UserId = initByUser.id,
UserIPAddress = initByUser.ipAddress,
UserRoles = initByUser.roles,
UserPrincipalName = tostring(initByUser.userPrincipalName),
TargetUserPrincipalName = tostring(TargetResources.userPrincipalName)
| where GroupName in~ (PrivilegedGroups)
// If you don't want to alert for operations from PIM, remove below filtering for MS-PIM.
| where InitiatedByDisplayName != "MS-PIM"
| project TimeGenerated, AADOperationType, Category, OperationName, AADTenantId, AppId, InitiatedByDisplayName, ServicePrincipalId, ServicePrincipalName, DisplayName, GroupName, UserId, UserIPAddress, UserRoles, UserPrincipalName, TargetUserPrincipalName
| extend timestamp = TimeGenerated, AccountCustomEntity = case(isnotempty(ServicePrincipalName), ServicePrincipalName, isnotempty(ServicePrincipalId), ServicePrincipalId, isnotempty(UserPrincipalName), UserPrincipalName, "not available")
EOF
    
  
    entity_mappings = [
      {
        entity_type = "Account"
        identifier = "FullName"
        field_name = "AccountCustomEntity"
         
      },
      {
        entity_type = "Account"
        identifier = "FullName"
        field_name = "TargetUserPrincipalName"
         
      } 
    ]

    tactics              = ["Persistence","PrivilegeEscalation"]
    techniques           = ["T1078","T1098"]

    display_name = "User added to Azure Active Directory Privileged Groups"
    description =  <<EOT
This will alert when a user is added to any of the Privileged Groups.
For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities.
For Administrator role permissions in Azure Active Directory please see https://docs.microsoft.com/azure/active-directory/users-groups-roles/directory-assign-admin-roles
EOT

    enabled = true
    create_incident = true
    grouping_enabled = false
    reopen_closed_incidents = false
    lookback_duration = "PT5H"
    entity_matching_method = "AllEntities"
    group_by_entities = []
    group_by_alert_details = ["Severity"]
    suppression_duration = "PT5H"
    suppression_enabled  = false
    event_grouping = "SingleAlert"
  }, # End Alert


  "Add_User_Admin_Group_365_Group" = {
    query_frequency      = "PT5H"
    query_period         = "PT5H"
    severity             = "Medium"

    query                = <<EOF
OfficeActivity 
| where ((Operation == "Add member to group") and (ResultStatus == "Success") and (ModifiedProperties contains "admin"))
| extend AccountCustomEntity = UserId, IPCustomEntity = ClientIP
EOF
    
  
    entity_mappings = [
      {
        entity_type = "Account"
        identifier = "FullName"
        field_name = "AccountCustomEntity"
         
      },
      {
        entity_type = "IP"
        identifier = "Address"
        field_name = "IPCustomEntity"
         
      } 
    ]

    tactics              = ["Persistence"]
    techniques           = ["T1098"]

    display_name = "Add a User to an Admin Group (via office365)"
    description =  <<EOT
Added a user to an admin group in Office 365. Technique: T1098.
EOT

    enabled = true
    create_incident = true
    grouping_enabled = false
    reopen_closed_incidents = false
    lookback_duration = "PT5H"
    entity_matching_method = "AllEntities"
    group_by_entities = []
    group_by_alert_details = ["Severity"]
    suppression_duration = "PT5H"
    suppression_enabled  = false
    event_grouping = "SingleAlert"
  }, # End Alert

  "User_Added_To_Admin_365_Role" = {
    query_frequency      = "PT1H"
    query_period         = "PT1H"
    severity             = "Medium"

    query                = <<EOF
OfficeActivity 
| where ((ModifiedProperties contains "admin") and (Operation == "Add member to role") and (ResultStatus == "Success"))
| extend AccountCustomEntity = UserId
| extend IPCustomEntity = ClientIP
EOF
    
  
    entity_mappings = [
      {
        entity_type = "Account"
        identifier = "FullName"
        field_name = "AccountCustomEntity"
         
      },
      {
        entity_type = "IP"
        identifier = "Address"
        field_name = "IPCustomEntity"
         
      }
    ]

    tactics              = ["Persistence"]
    techniques           = ["T1078"]

    display_name = "Add a User to an Admin Role (via office365)"
    description =  <<EOT
Added a user to an admin role in Office 365. Technique: T1098.
EOT

    enabled = true
    create_incident = true
    grouping_enabled = false
    reopen_closed_incidents = false
    lookback_duration = "PT5H"
    entity_matching_method = "AllEntities"
    group_by_entities = []
    group_by_alert_details = ["Severity"]
    suppression_duration = "PT5H"
    suppression_enabled  = false
    event_grouping = "SingleAlert"
  }, # End Alert

  "Privileged_Role_Oustide_PIM" = {
    query_frequency      = "P1D"
    query_period         = "P1D"
    severity             = "Low"

    query                = <<EOF
AuditLogs
| where Category =~ "RoleManagement"
| where OperationName has "Add member to role outside of PIM"
        or (LoggedByService == "Core Directory" and OperationName == "Add member to role" and Identity !has "MS-PIM")
| extend AccountCustomEntity = tostring(TargetResources[0].userPrincipalName), IPCustomEntity = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)
EOF
    
  
    entity_mappings = [
      {
        entity_type = "Account"
        identifier = "FullName"
        field_name = "AccountCustomEntity"
         
      },
      {
        entity_type = "IP"
        identifier = "Address"
        field_name = "IPCustomEntity"
         
      }
    ]

    tactics              = ["PrivilegeEscalation"]
    techniques           = ["T1078"]

    display_name = "Privileged Role Assigned Outside PIM"
    description =  <<EOT
Identifies a privileged role being assigned to a user outside of PIM
Ref : https://docs.microsoft.com/azure/active-directory/fundamentals/security-operations-privileged-accounts#things-to-monitor-1
EOT

    enabled = true
    create_incident = true
    grouping_enabled = false
    reopen_closed_incidents = false
    lookback_duration = "P1D"
    entity_matching_method = "AllEntities"
    group_by_entities = []
    group_by_alert_details = ["Severity"]
    suppression_duration = "P1D"
    suppression_enabled  = false
    event_grouping = "SingleAlert"
  }, # End Alert

  "Multiple_Admin_Removal_New_Admin" = {
    query_frequency      = "PT1H"
    query_period         = "P7D"
    severity             = "Medium"

    query                = <<EOF
let lookback = 7d; 
let timeframe = 1h; 
let GlobalAdminsRemoved = AuditLogs 
| where TimeGenerated > ago(timeframe) 
| where Category =~ "RoleManagement" 
| where AADOperationType in ("Unassign", "RemoveEligibleRole") 
| where ActivityDisplayName has_any ("Remove member from role", "Remove eligible member from role") 
| mv-expand TargetResources 
| mv-expand TargetResources.modifiedProperties 
| extend displayName_ = tostring(TargetResources_modifiedProperties.displayName) 
| where displayName_ =~ "Role.DisplayName" 
| extend RoleName = tostring(parse_json(tostring(TargetResources_modifiedProperties.oldValue))) 
| where RoleName == "Global Administrator" // Add other Privileged role if applicable 
| extend InitiatingApp = tostring(parse_json(tostring(InitiatedBy.app)).displayName) 
| extend Initiator = iif(isnotempty(InitiatingApp), InitiatingApp, tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)) 
| where Initiator != "MS-PIM"  // Filtering PIM events 
| extend Target = tostring(TargetResources.userPrincipalName) 
| summarize RemovedGlobalAdminTime = max(TimeGenerated), TargetAdmins = make_set(Target) by OperationName,  RoleName, Initiator, Result; 
let GlobalAdminsAdded = AuditLogs 
| where TimeGenerated > ago(lookback) 
| where Category =~ "RoleManagement" 
| where AADOperationType in ("Assign", "AssignEligibleRole") 
| where ActivityDisplayName has_any ("Add eligible member to role", "Add member to role") and Result == "success" 
| mv-expand TargetResources 
| mv-expand TargetResources.modifiedProperties 
| extend displayName_ = tostring(TargetResources_modifiedProperties.displayName) 
| where displayName_ =~ "Role.DisplayName" 
| extend RoleName = tostring(parse_json(tostring(TargetResources_modifiedProperties.newValue))) 
| where RoleName == "Global Administrator" // Add other Privileged role if applicable 
| extend InitiatingApp = tostring(parse_json(tostring(InitiatedBy.app)).displayName) 
| extend Initiator = iif(isnotempty(InitiatingApp), InitiatingApp, tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)) 
| where Initiator != "MS-PIM"  // Filtering PIM events 
| extend Target = tostring(TargetResources.userPrincipalName) 
| summarize AddedGlobalAdminTime = max(TimeGenerated) by OperationName,  RoleName, Target, Initiator, Result 
| extend AccountCustomEntity = Target; 
GlobalAdminsAdded 
| join kind= inner GlobalAdminsRemoved on $left.Target == $right.Initiator 
| where AddedGlobalAdminTime < RemovedGlobalAdminTime 
| extend NoofAdminsRemoved = array_length(TargetAdmins) 
| where NoofAdminsRemoved > 1
| project AddedGlobalAdminTime, Initiator, Target, AccountCustomEntity, RemovedGlobalAdminTime, TargetAdmins, NoofAdminsRemoved
EOF
    
  
    entity_mappings = [
      {
        entity_type = "Account"
        identifier = "FullName"
        field_name = "AccountCustomEntity"
         
      }
    ]

    tactics              = ["Impact"]
    techniques           = ["T1531"]

    display_name = "Multiple admin membership removals from newly created admin"
    description =  <<EOT
This query detects when newly created Global admin removes multiple existing global admins which can be an attempt by adversaries to lock down organization and retain sole access. 
 Investigate reasoning and intention of multiple membership removal by new Global admins and take necessary actions accordingly.
EOT

    enabled = true
    create_incident = true
    grouping_enabled = false
    reopen_closed_incidents = false
    lookback_duration = "P1D"
    entity_matching_method = "AllEntities"
    group_by_entities = []
    group_by_alert_details = ["Severity"]
    suppression_duration = "P1D"
    suppression_enabled  = false
    event_grouping = "SingleAlert"
  }, # End Alert

  } # End Alert Rules
} # End locals
 