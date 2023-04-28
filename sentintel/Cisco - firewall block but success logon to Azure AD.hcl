resource "my_alert_rule" "rule_331" {
  name = "Cisco - firewall block but success logon to Azure AD"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
let aadFunc = (tableName:string){
CommonSecurityLog
| where DeviceVendor =~ "Cisco"
| where DeviceAction =~ "denied"
| where ipv4_is_private(SourceIP) == false
| summarize count() by SourceIP
| join (
    // Successful signins from IPs blocked by the firewall solution are suspect
    // Include fully successful sign-ins, but also ones that failed only at MFA stage
    // as that supposes the password was sucessfully guessed.
  table(tableName)
  | where ResultType in ("0", "50074", "50076") 
) on $left.SourceIP == $right.IPAddress
| extend timestamp = TimeGenerated, IPCustomEntity = SourceIP, AccountCustomEntity = UserPrincipalName
};
let aadSignin = aadFunc("SigninLogs");
let aadNonInt = aadFunc("AADNonInteractiveUserSignInLogs");
union isfuzzy=true aadSignin, aadNonInt
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
  tactics = ['InitialAccess']
  techniques = ['T1078']
  display_name = Cisco - firewall block but success logon to Azure AD
  description = <<EOT
Correlate IPs blocked by a Cisco firewall appliance with successful Azure Active Directory signins. 
Because the IP was blocked by the firewall, that same IP logging on successfully to AAD is potentially suspect
and could indicate credential compromise for the user account.
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
