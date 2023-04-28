resource "my_alert_rule" "rule_172" {
  name = "System audit policy was changed"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT10M
  query_period = PT10M
  severity = Low
  query = <<EOF
let AuditEventDataLookup_Func = (ID: string) {
 dynamic(
{"%%8272":"System",
"%%8273":"Logon/Logoff",
"%%8274":"Object Access",
"%%8275":"Privilege Use",
"%%8276":"Detailed Tracking",
"%%8277":"Policy Change",
"%%8278":"Account Management",
"%%8279":"DS Access",
"%%8280":"Account Logon",
"%%12288":"Security State Change",
"%%12289":"Security System Extension",
"%%12290":"System Integrity",
"%%12291":"IPsec Driver",
"%%12292":"Other System Events",
"%%12544":"Logon",
"%%12545":"Logoff",
"%%12546":"Account Lockout",
"%%12547":"IPsec Main Mode",
"%%12548":"Special Logon",
"%%12549":"IPsec Quick Mode",
"%%12550":"IPsec Extended Mode",
"%%12551":"Other Logon/Logoff Events",
"%%12552":"Network Policy Server",
"%%12553":"User/Device Claims",
"%%12554":"Group Membership",
"%%12800":"File System",
"%%12801":"Registry",
"%%12802":"Kernel Object",
"%%12803":"SAM",
"%%12804":"Other Object Access Events",
"%%12805":"Certification Services",
"%%12806":"Application Generated",
"%%12807":"Handle Manipulation",
"%%12808":"File Share",
"%%12809":"Filtering Platform Packet Drop",
"%%12810":"Filtering Platform Connection",
"%%12811":"Detailed File Share",
"%%12812":"Removable Storage",
"%%12813":"Central Policy Staging",
"%%13056":"Sensitive Privilege Use",
"%%13057":"Non Sensitive Privilege Use",
"%%13058":"Other Privilege Use Events",
"%%13312":"Process Creation",
"%%13313":"Process Termination",
"%%13314":"DPAPI Activity",
"%%13315":"RPC Events",
"%%13316":"Plug and Play Events",
"%%13317":"Token Right Adjusted Events",
"%%13568":"Audit Policy Change",
"%%13569":"Authentication Policy Change",
"%%13570":"Authorization Policy Change",
"%%13571":"MPSSVC Rule-Level Policy Change",
"%%13572":"Filtering Platform Policy Change",
"%%13573":"Other Policy Change Events",
"%%13824":"User Account Management",
"%%13825":"Computer Account Management",
"%%13826":"Security Group Management",
"%%13827":"Distribution Group Management",
"%%13828":"Application Group Management",
"%%13829":"Other Account Management Events",
"%%14080":"Directory Service Access",
"%%14081":"Directory Service Changes",
"%%14082":"Directory Service Replication",
"%%14083":"Detailed Directory Service Replication",
"%%14336":"Credential Validation",
"%%14337":"Kerberos Service Ticket Operations",
"%%14338":"Other Account Logon Events",
"%%14339":"Kerberos Authentication Service",
"%%8448":"Success removed",
"%%8449":"Success Added",
"%%8450":"Failure removed",
"%%8451":"Failure added",
"%%8452":"Success include removed",
"%%8453":"Success include added",
"%%8454":"Success exclude removed",
"%%8455":"Success exclude added",
"%%8456":"Failure include removed",
"%%8457":"Failure include added",
"%%8458":"Failure exclude removed",
"%%8459":"Failure exclude added"
})[ID]
};
SecurityEvent
| where TimeGenerated >= ago(24hr)
| where EventID == 4719
| where SubjectUserSid !contains "S-1-5-18"
| extend Category = AuditEventDataLookup_Func(CategoryId)
| extend SubCategory = AuditEventDataLookup_Func(SubcategoryId)
| extend AuditPolicyChangesParse = parse_csv(AuditPolicyChanges)
| extend AuditPolicyChange = trim_end(",", strcat(AuditEventDataLookup_Func(AuditPolicyChangesParse[0]), ",", AuditEventDataLookup_Func(trim(" ", tostring(AuditPolicyChangesParse[1])))))
| where not (SubCategory has_any("IPsec Main Mode", "IPsec Quick Mode", " IPsec Extended Mode", "Other Logon/Logoff Events", "Network Policy Server", "Kernel Object", "Handle Manipulation", "Filtering Platform Packet Drop", "Other Privilege Use Events", "Process Termination", "DPAPI Activity", "RPC Events", "Directory Service Replication", "Detailed Directory Service Replication", "Credential Validation", "Other Account Logon Events"))
| where AuditPolicyChange has_any ("Success")
| extend EventData = parse_xml(EventData).EventData.Data
| mv-expand bagexpansion = array EventData
| evaluate bag_unpack(EventData)
| project TimeGenerated, Computer, Activity, Category, SubCategory, AuditPolicyChange, Account
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = Name
      column_name = Account
    }
    entity_type = Host
    field_mappings {
      identifier = HostName
      column_name = Computer
    }
  }
  tactics = ['DefenseEvasion']
  techniques = ['T1562']
  display_name = System audit policy was changed
  description = <<EOT
This event generates when the computer's audit policy changes. This event is always logged regardless of the "Audit Policy Change" sub-category setting. If group policy was used to configure audit policy unfortunately the Subject fields don't identify who actually changed the policy. In such cases this event always shows the local computer as the one who changed the policy since the computer is the security principal under which gpupdate runs.
EOT
  enabled = True
  create_incident = True
  grouping_configuration {
    enabled = True
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
