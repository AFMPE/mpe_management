resource "my_alert_rule" "rule_259" {
  name = "Linked Malicious Storage Artifacts"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Medium
  query = <<EOF
//Collect the alert events
let alertData = SecurityAlert 
| where DisplayName has "Potential malware uploaded to" 
| extend Entities = parse_json(Entities) 
| mv-expand Entities;
//Parse the IP address data
let ipData = alertData 
| where Entities['Type'] =~ "ip" 
| extend AttackerIP = tostring(Entities['Address']), AttackerCountry = tostring(Entities['Location']['CountryName']);
//Parse the file data
let FileData = alertData 
| where Entities['Type'] =~ "file" 
| extend MaliciousFileDirectory = tostring(Entities['Directory']), MaliciousFileName = tostring(Entities['Name']), MaliciousFileHashes = tostring(Entities['FileHashes']);
//Combine the File and IP data together
ipData 
| join (FileData) on VendorOriginalId 
| summarize by TimeGenerated, AttackerIP, AttackerCountry, DisplayName, ResourceId, AlertType, MaliciousFileDirectory, MaliciousFileName, MaliciousFileHashes
//Create a type column so we can track if it was a File storage or blobl storage upload 
| extend type = iff(DisplayName has "file", "File", "Blob") 
| join (
  union
  StorageFileLogs, 
  StorageBlobLogs 
  //File upload operations 
  | where OperationName =~ "PutBlob" or OperationName =~ "PutRange"
  //Parse out the uploader IP 
  | extend ClientIP = tostring(split(CallerIpAddress, ":", 0)[0])
  //Extract the filename from the Uri 
  | extend FileName = extract(@"\/([\w\-. ]+)\?", 1, Uri)
  //Base64 decode the MD5 filehash, we will encounter non-ascii hex so string operations don't work
  //We can work around this by making it an array then converting it to hex from an int 
  | extend base64Char = base64_decode_toarray(ResponseMd5) 
  | mv-expand base64Char 
  | extend hexChar = tohex(toint(base64Char))
  | extend hexChar = iff(strlen(hexChar) < 2, strcat("0", hexChar), hexChar) 
  | extend SourceTable = iff(OperationName has "range", "StorageFileLogs", "StorageBlobLogs") 
  | summarize make_list(hexChar) by CorrelationId, ResponseMd5, FileName, AccountName, TimeGenerated, RequestBodySize, ClientIP, SourceTable 
  | extend Md5Hash = strcat_array(list_hexChar, "")
  //Pack the file information the summarise into a ClientIP row 
  | extend p = pack("FileName", FileName, "FileSize", RequestBodySize, "Md5Hash", Md5Hash, "Time", TimeGenerated, "SourceTable", SourceTable) 
  | summarize UploadedFileInfo=make_list(p), FilesUploaded=count() by ClientIP 
      | join kind=leftouter (
        union
        StorageFileLogs,
        StorageBlobLogs               
        | where OperationName =~ "DeleteFile" or OperationName =~ "DeleteBlob"         
        | extend ClientIP = tostring(split(CallerIpAddress, ":", 0)[0])         
        | extend FileName = extract(@"\/([\w\-. ]+)\?", 1, Uri)         
        | extend SourceTable = iff(OperationName has "range", "StorageFileLogs", "StorageBlobLogs")         
        | extend p = pack("FileName", FileName, "Time", TimeGenerated, "SourceTable", SourceTable)         
        | summarize DeletedFileInfo=make_list(p), FilesDeleted=count() by ClientIP
        ) on ClientIP
  ) on $left.AttackerIP == $right.ClientIP 
| mvexpand UploadedFileInfo 
| extend LinkedMaliciousFileName = UploadedFileInfo.FileName 
| extend LinkedMaliciousFileHash = UploadedFileInfo.Md5Hash     
| project AlertTimeGenerated = TimeGenerated, tostring(LinkedMaliciousFileName), tostring(LinkedMaliciousFileHash), AlertType, AttackerIP, AttackerCountry, MaliciousFileDirectory, MaliciousFileName, FilesUploaded, UploadedFileInfo 
| extend FileHashCustomEntity = LinkedMaliciousFileName, HashAlgorithm = "MD5", IPCustomEntity = AttackerIP
EOF
  entity_mapping {
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPCustomEntity
    }
    entity_type = FileHash
    field_mappings {
      identifier = Algorithm
      column_name = HashAlgorithm
      identifier = Value
      column_name = FileHashCustomEntity
    }
  }
  tactics = ['CommandAndControl', 'Exfiltration']
  techniques = ['T1071', 'T1567']
  display_name = Linked Malicious Storage Artifacts
  description = <<EOT
An IP address which uploaded malicious content to an Azure Blob or File Storage container (triggering a malware alert) also uploaded additional files.
EOT
  enabled = True
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
