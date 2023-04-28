resource "my_alert_rule" "rule_332" {
  name = "Svchost spawning Cmd"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = PT1H
  severity = Medium
  query = <<EOF
let SE = (SecurityEvent
    | where ParentProcessName has "svchost.exe" and Process == "cmd.exe"
    | project TimeGenerated, Computer, Account, ProcessCommandLine = CommandLine);
let DfE = (DeviceProcessEvents
    | where InitiatingProcessFileName has "svchost.exe" and FileName has "cmd.exe"
    | project TimeGenerated, Computer = DeviceName, Account = AccountName, ProcessCommandLine);
SE
| union DfE
| where ProcessCommandLine <> ""
| where not (ProcessCommandLine has_any ("C:\\Program Files\\ConnectWise", '"HFMPRE_ForceStart.bat"', '"HFM_ForceStart.bat"', '"DynCorp_i2_GAINS_ARO.bat"', '"D:\\IAConnect\\ReportDataCapture\\RunBatch.bat"', 'C:\\SolutionsBatch\\Person.bat', "C:\\Windows\\system32\\silcollector.cmd", "D:\\GAINS\\Gains_Home\\Batch\\Project\\DynCorp_GAINS_Process.bat", "D:\\GAINS\\Gains_Home\\Batch\\Project\\rawDataArchiver.bat", "D:\\GainsInterface\\CopyProductionExportFile.cmd", "C:\\ASSYSTINTG\\CUG_Imports\\PeopleSoft Contact User-PROD.bat", "C:\\ASSYSTINTG\\CUG_Imports\\PeopleSoft Contact User-PROD.bat", "C:\\TaleoProject\\DWH Touchpoint\\bin\\Windows", "C:\\Batch\\PowerOn.bat", "C:\\AD Import\\Script\\imports.bat", "D:\\Scripts\\RefreshHFM.bat", "C:\\Batch\\started.bat", "C:\\Program Files\\Npcap", "E:\\Wise73\\scripts", "CAD Admin", "CAD_Admin", "FedExAdminService", "C:\\Temp\\BitLocker_Key_Backup.bat", "D:\\DMS_Apps\\WarehouseItemScanListener\\CopyScanFilesToAzureVM.bat", "start hpdiags", "profile_settings", "hptpsmarthealthservice", "UdtFileMove.bat", "WellsfargoMove.bat", "UDTSOPOMove.bat", "eBridgeClean.bat", "TranFileMove.bat", "novamove.bat", "vsmove.bat", "abtsvchost", "C:\\Windows\\Cluster", "C:\\WINDOWS\\System32\\LxRun.exe", "backupForayAdams.bat", "C:\\Program Files\\Cellebrite Mobile Synchronization", "syncCustodies.bat", "runlinx.bat", "ArchiveLogs.bat", "CAbackups.bat", "deletepst.bat", "Restart PDQ.bat", "iissetup.exe /keygen", "Lspush.exe", "flushdns", "WISEDBBackup", "RevenueExpensesAnalysis.bat", "EquipInventory.bat", "CN Analysis.bat", "r4sysidcheck.bat", "C:\\Program Files\\Pulseway", "C:\\Program Files (x86)\\ThousandEyes\\Npcap", "C:\\ProgramData\\MedNX\\OfficeNode\\ServiceStatus.bat", "pandoratool.bat", "pandoracron.bat", "voyagerevenue.bat", "Voyage Revenue BI.bat", "ManagementReporting.bat", "WindowsDefenderATPOnboardingScript.cmd", "\\scripts\\Defender\\WindowsDefenderATPLocalOnboardingScript.cmd", "WindowsDefenderATPOnboardingScript", "WindowsDefenderATPOnboardingScript_NEW.cmd", "\\SMBConnectivityPatch\\step1.bat", "\\Npcap\\CheckStatus.bat", "\\Batches\\UserMatrix.bat", "\\Batches\\UserMatrixNoIT.bat", "\\Batches\\SalesInformation.bat", "\\Batches\\voyagefinancial_JDE9.2.bat", "\\AppData\\Local\\ilmtscriptdev.bat", "\\AppData\\Local\\ilmtscript.bat", "\\Sage\\Backup\\backupCleanup.bat", "\\Softship\\Services\\Scheduler_autorestarttask.bat", "cmd\\st0raDmp.bat", "ICS\\tools\\copy_only.bat", "TempZone\\Scanner\\ANF\\HP", "PROD\\AP_DROPOFFS\\APEXP", "ATL\\Scanner", "scanner", "HOUScanner", "OGC VUE", "UserReport", "Python Automations", "Smart3D-DBX", "get_webtools_log", "Aveva_Batch", "Navisworks", "SPARTA", "TARA", "FEAGOLEditTracking", "batchrestart", "workflow_folder_cleanup", "brava_filename_cleanup", "powerbi2", "Supreme_NWD", "smart3d", "sp2dsvc", "auto_tasks", "FME\\Scheduler", "PlayerLocationCheck", "FMAuditOnsite", "GlobalScan\\tools\\windows_scheduled_task", "RuleChecker_start", "Self_Assessment_Run", "Copy_CRL", "backup_MDL", "SingClientService", "connectmaster\\backup", "SingClient", "SpecLookUpRestart", "ThunderboltFW", "LenovoCleanupFolder", "Download_ADM_Soybeans", "APOD.bat", "Compact_db.bat", "backup_MDL.bat", "CJ-Work", "Self_Assessment_Run.bat", "ADSearch.bat", "softdist\\Bmcd", "Navisworks_Tasks", "LCAT", "NavisworksStaging", "Autodesk", "TimeSheet.cmd", "S3D Tasks", "BAT Files", "ArcGIS\\Pro", "Copy_files2.bat", "MoveFilesfromSubFolderstoPublicDocs.bat", "Backup_db.bat", "Backup_Full_Daily.bat", "CoSign Backups", "stoponbase.bat", "oleup", "wctsysdf", "o365-batch-file.bat"))
| where not (ProcessCommandLine contains "E:\\Wise73\\scripts" or ProcessCommandLine contains "C:\\DataWarehouse\\automateArchiver.bat" or ProcessCommandLine contains "F:\\DataWarehouse\\runUnarchiver.bat")
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = Account
    }
    entity_type = Host
    field_mappings {
      identifier = HostName
      column_name = Computer
    }
  }
  tactics = ['Execution']
  techniques = ['T1059']
  display_name = svchost spawning Cmd
  description = <<EOT
'Identifies a suspicious parent-child process relationship with cmd.exe descending from svchost.exe.'

EOT
  enabled = True
  create_incident = True
  grouping_configuration {
    enabled = True
    reopen_closed_incident = False
    lookback_duration = PT5H
    entity_matching_method = AllEntities
    group_by_entities = []
    group_by_alert_details = []
    group_by_custom_details = []
  }
  suppression_duration = PT5M
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
