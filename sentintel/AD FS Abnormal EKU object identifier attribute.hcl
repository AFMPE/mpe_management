resource "my_alert_rule" "rule_318" {
  name = "AD FS Abnormal EKU object identifier attribute"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = P1D
  severity = High
  query = <<EOF
// change the starttime value for a longer period of known OIDs
let starttime = 1d;
// change the lookback value for a longer period of lookback for suspicious/abnormal
let lookback = 1h;
let OIDList = SecurityEvent
| where TimeGenerated >= ago(starttime)
| where EventSourceName == 'AD FS Auditing'
| where EventID == 501
| where EventData has '/eku'
| extend OIDs = extract_all(@"<Data>([\d+\.]+)</Data>", EventData)
| mv-expand OIDs
| extend OID = tostring(OIDs)
| extend OID_Length = strlen(OID)
| project TimeGenerated, Computer, EventSourceName, EventID, OID, OID_Length, EventData
;
OIDList
| where TimeGenerated >= ago(lookback)
| join kind=leftanti (
OIDList
| where TimeGenerated between (ago(starttime) .. ago(lookback))
| summarize by OID
) on OID
EOF
  entity_mapping {
    entity_type = Host
    field_mappings {
      identifier = FullName
      column_name = Computer
    }
  }
  tactics = ['CredentialAccess']
  techniques = ['T1552']
  display_name = AD FS Abnormal EKU object identifier attribute
  description = <<EOT
This detection uses Security events from the "AD FS Auditing" provider to detect suspicious object identifiers (OIDs) as part EventID 501 and specifically part of the Enhanced Key Usage attributes.
This query checks to see if you have any new OIDs in the last hour that have not been seen in the previous day. New OIDs should be validated and OIDs that are very long, as indicated
by the OID_Length field, could also be an indicator of malicious activity.
In order to use this query you need to enable AD FS auditing on the AD FS Server.
References:
https://www.microsoft.com/security/blog/2022/08/24/magicweb-nobeliums-post-compromise-trick-to-authenticate-as-anyone/
https://docs.microsoft.com/windows-server/identity/ad-fs/troubleshooting/ad-fs-tshoot-logging

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
