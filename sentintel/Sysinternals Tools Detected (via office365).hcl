resource "my_alert_rule" "rule_158" {
  name = "Sysinternals Tools Detected (via office365)"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5H
  query_period = PT5H
  severity = Medium
  query = <<EOF
OfficeActivity 
| where ((Operation == "FileUploaded" or Operation == "FileAccessed" or Operation == "FileDownloaded") and (SourceFileName == "AccessEnum.exe" or SourceFileName == "AdExplorer.exe" or SourceFileName == "AdInsight.exe" or SourceFileName == "AdRestore.exe" or SourceFileName == "Autologon.exe" or SourceFileName == "Autoruns.exe" or SourceFileName == "BgInfo.exe" or SourceFileName == "CacheSet.exe" or SourceFileName == "ClockRes.exe" or SourceFileName == "Contig.exe" or SourceFileName == "Coreinfo.exe" or SourceFileName == "Ctrl2Cap.exe" or SourceFileName == "DebugView.exe" or SourceFileName == "Desktops.exe" or SourceFileName == "Disk2vhd.exe" or SourceFileName == "DiskExt.exe" or SourceFileName == "DiskMon.exe" or SourceFileName == "DiskView.exe" or SourceFileName == "EFSDump.exe" or SourceFileName == "FindLinks.exe" or SourceFileName == "Handle.exe" or SourceFileName == "Hex2dec.exe" or SourceFileName == "Junction.exe" or SourceFileName == "LDMDump.exe" or SourceFileName == "ListDLLs.exe" or SourceFileName == "LiveKd.exe" or SourceFileName == "LoadOrder.exe" or SourceFileName == "LogonSessions.exe" or SourceFileName == "PipeList.exe" or SourceFileName == "PortMon.exe" or SourceFileName == "ProcDump.exe" or SourceFileName == "ProcMon.exe" or SourceFileName == "PsFile.exe" or SourceFileName == "PsGetSid.exe" or SourceFileName == "PsInfo.exe" or SourceFileName == "PsKill.exe" or SourceFileName == "PsList.exe" or SourceFileName == "PsLogList.exe" or SourceFileName == "PsLoggedOn.exe" or SourceFileName == "PsPasswd.exe" or SourceFileName == "PsPing.exe" or SourceFileName == "PsService.exe" or SourceFileName == "PsShutdown.exe" or SourceFileName == "PsSuspend.exe" or SourceFileName == "RAMMap.exe" or SourceFileName == "RegDelNull.exe" or SourceFileName == "RegJump.exe" or SourceFileName == "SDelete.exe" or SourceFileName == "ShareEnum.exe" or SourceFileName == "ShellRunas.exe" or SourceFileName == "Sigcheck.exe" or SourceFileName == "Streams.exe" or SourceFileName == "Strings.exe" or SourceFileName == "Sysmon.exe" or SourceFileName == "TCPView.exe" or SourceFileName == "WhoIs.exe" or SourceFileName == "WinObj.exe" or SourceFileName == "ZoomIt.exe" or SourceFileName == "pipelist.exe" or SourceFileName == "procexp.exe" or SourceFileName == "psexec.exe" or SourceFileName == "ru.exe"))
| project-rename AccountCustomEntity = UserId, LocationLink = OfficeObjectId, IPCustomEntity = ClientIP, SysInternalFile=SourceFileName
| project AccountCustomEntity, LocationLink, IPCustomEntity, SysInternalFile, UserAgent
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
  tactics = ['CredentialAccess']
  techniques = ['T1003']
  display_name = Sysinternals Tools Detected (via office365)
  description = <<EOT
Can be used for offensive perspective. Technique: T1204.
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
