resource "my_alert_rule" "rule_30" {
  name = "Anomalous login followed by Teams action"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P14D
  severity = Medium
  query = <<EOF
//The bigger the window the better the data sample size, as we use IP prevalence, more sample data is better.
//The minimum number of countries that the account has been accessed from [default: 2]
let minimumCountries = 2;
//The delta (%) between the largest in-use IP and the smallest [default: 95]
let deltaThreshold = 95;
//The maximum (%) threshold that the country appears in login data [default: 10]
let countryPrevalenceThreshold = 10;
//The time to project forward after the last login activity [default: 60min]
let projectedEndTime = 60m;
let queryfrequency = 1d;
let queryperiod = 14d;
let aadFunc = (tableName: string) {
    // Get successful signins to Teams
    let signinData =
        table(tableName)
        | where TimeGenerated > ago(queryperiod)
        | where AppDisplayName has "Teams" and ConditionalAccessStatus =~ "success"
        | extend Country = tostring(todynamic(LocationDetails)['countryOrRegion'])
        | where isnotempty(Country) and isnotempty(IPAddress);
    // Calculate prevalence of countries
    let countryPrevalence =
        signinData
        | summarize CountCountrySignin = count() by Country
        | extend TotalSignin = toscalar(signinData
            | summarize count())
        | extend CountryPrevalence = toreal(CountCountrySignin) / toreal(TotalSignin) * 100;
    // Count signins by user and IP address
    let userIpSignin =
        signinData
        | summarize
            CountIPSignin = count(),
            Country = any(Country),
            ListSigninTimeGenerated = make_list(TimeGenerated)
            by IPAddress, UserPrincipalName;
    // Calculate delta between the IP addresses with the most and minimum activity by user
    let userIpDelta =
        userIpSignin
        | summarize
            MaxIPSignin = max(CountIPSignin),
            MinIPSignin = min(CountIPSignin),
            DistinctCountries = dcount(Country),
            make_set(Country)
            by UserPrincipalName
        | extend UserIPDelta = toreal(MaxIPSignin - MinIPSignin) / toreal(MaxIPSignin) * 100;
    // Collect Team operations the user account has performed within a time range of the suspicious signins
    OfficeActivity
    | where TimeGenerated > ago(queryfrequency)
| where Operation in~ ("TeamsAdminAction", "MemberAdded", "MemberRemoved", "MemberRoleChanged", "AppInstalled", "BotAddedToTeam")
| extend Added_Members = tostring(parse_json(parse_json(Members)[0]).UPN)
| project OperationTimeGenerated = TimeGenerated, UserId = tolower(UserId), Operation,  Added_Members,ChatName, CommunicationType
| join kind = inner(
        userIpDelta
        // Check users with activity from distinct countries
        | where DistinctCountries >= minimumCountries
        // Check users with high IP delta
        | where UserIPDelta >= deltaThreshold
        // Add information about signins and countries
        | join kind = leftouter userIpSignin on UserPrincipalName
        | join kind = leftouter countryPrevalence on Country
        // Check activity that comes from nonprevalent countries
        | where CountryPrevalence < countryPrevalenceThreshold
        | project
            UserPrincipalName,
            SuspiciousIP = IPAddress,
            UserIPDelta,
            SuspiciousSigninCountry = Country,
            SuspiciousCountryPrevalence = CountryPrevalence,
            EventTimes = ListSigninTimeGenerated
        )
        on $left.UserId == $right.UserPrincipalName
    // Check the signins occured 60 min before the Teams operations
    | mv-expand SigninTimeGenerated = EventTimes
    | extend SigninTimeGenerated = todatetime(SigninTimeGenerated)
    | where OperationTimeGenerated between (SigninTimeGenerated .. (SigninTimeGenerated + projectedEndTime))
};
let aadSignin = aadFunc("SigninLogs");
let aadNonInt = aadFunc("AADNonInteractiveUserSignInLogs");
union isfuzzy=true aadSignin, aadNonInt
| summarize arg_max(SigninTimeGenerated, *) by UserPrincipalName, SuspiciousIP, OperationTimeGenerated
| summarize
    ActivitySummary = make_bag(pack(tostring(SigninTimeGenerated), pack("Operation", tostring(Operation), "OperationTime", OperationTimeGenerated)))
    by
    UserPrincipalName,
    Added_Members,
    SuspiciousIP,
    SuspiciousSigninCountry,
    SuspiciousCountryPrevalence,
    ChatName,
    CommunicationType
| extend IPCustomEntity = SuspiciousIP, AccountCustomEntity = UserPrincipalName
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
  tactics = ['InitialAccess', 'Persistence']
  techniques = ['T1078', 'T1199', 'T1136', 'T1098']
  display_name = Anomalous login followed by Teams action
  description = <<EOT
Detects anomalous IP address usage by user accounts and then checks to see if a suspicious Teams action is performed.
Query calculates IP usage Delta for each user account and selects accounts where a delta >= 90% is observed between the most and least used IP.
To further reduce results the query performs a prevalence check on the lowest used IP's country, only keeping IP's where the country is unusual for the tenant (dynamic ranges)
Finally the user accounts activity within Teams logs is checked for suspicious commands (modifying user privileges or admin actions) during the period the suspicious IP was active.
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
