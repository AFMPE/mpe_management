resource "my_alert_rule" "rule_103" {
  name = "New executable via Office FileUploaded Operation"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P8D
  severity = Low
  query = <<EOF
// a threshold can be enabled, see commented line below for PrevSeenCount
//let threshold = 2;
let uploadOp = 'FileUploaded';
// Extensions that are interesting. Add/Remove to this list as you see fit
let execExt = dynamic(['exe', 'inf', 'gzip', 'cmd', 'bat']);
let starttime = 8d;
let endtime = 1d;
OfficeActivity 
| where TimeGenerated >= ago(endtime)
// Limited to File Uploads due to potential noise, comment out the Operation statement below to include any operation type
// Additional, but potentially noisy operation types that include Uploads and Downloads can be included by adding the following - Operation contains "upload" or Operation contains "download"
| where Operation =~ uploadOp
| where SourceFileExtension has_any (execExt)
| project TimeGenerated, OfficeId, OfficeWorkload, RecordType, Operation, UserType, UserKey, UserId, ClientIP, UserAgent, Site_Url, SourceRelativeUrl, SourceFileName
| join kind= leftanti (
OfficeActivity | where TimeGenerated between (ago(starttime) .. ago(endtime))
| where Operation =~ uploadOp
| where SourceFileExtension has_any (execExt)
| summarize SourceRelativeUrl = make_set(SourceRelativeUrl), UserId = make_set(UserId) , PrevSeenCount = count() by SourceFileName
// To exclude previous matches when only above a specific count, change threshold above and uncomment the line below
//| where PrevSeenCount > threshold
| mvexpand SourceRelativeUrl, UserId
| extend SourceRelativeUrl = tostring(SourceRelativeUrl), UserId = tostring(UserId)
) on SourceFileName, SourceRelativeUrl, UserId 
| extend SiteUrlUserFolder = tolower(split(Site_Url, '/')[-2])
| extend UserIdUserFolderFormat = tolower(replace('@|\\.', '_',UserId))
// identify when UserId is not a match to the specific site url personal folder reference
| extend UserIdDiffThanUserFolder = iff(Site_Url has '/personal/' and SiteUrlUserFolder != UserIdUserFolderFormat, true , false )
| distinct SourceFileName, UserId, ClientIP, UserAgent, Site_Url, SourceRelativeUrl
| join kind=inner (OfficeActivity 
| where (Operation == "FileMalwareDetected")
| project SourceRelativeUrl, SourceFileName) on $left.SourceFileName == $right.SourceFileName and $left.SourceRelativeUrl == $right.SourceRelativeUrl
| project-away SourceFileName1, SourceRelativeUrl1
| extend AccountCustomEntity = UserId, IPCustomEntity = ClientIP, URLCustomEntity = Site_Url
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
    entity_type = URL
    field_mappings {
      identifier = Url
      column_name = URLCustomEntity
    }
  }
  tactics = ['CommandAndControl']
  techniques = ['T1105']
  display_name = New executable via Office FileUploaded Operation
  description = <<EOT
Identifies when executable file types are uploaded to Office services such as SharePoint and OneDrive.
List currently includes 'exe', 'inf', 'gzip', 'cmd', 'bat' file extensions.
Additionally, identifies when a given user is uploading these files to another users workspace.
Additionally, it cooralates these uploads with Malware alerts from Sharepoint AV engine. If the file is listed below it was found to be malicious.
This may be indication of a staging location for malware or other malicious activity.
EOT
  enabled = False
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
