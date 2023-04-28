resource "my_alert_rule" "rule_205" {
  name = "Base64 Encoding Detected"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT4H
  query_period = PT4H
  severity = Low
  query = <<EOF
union(SecurityEvent
    | extend SplitLaunchString = split(CommandLine, " ")
    | mvexpand SplitLaunchString
    | where SplitLaunchString matches regex "^[A-Za-z0-9+/]{50,}[=]{0,2}$"
    | extend Base64 = tostring(SplitLaunchString)
    | extend DecodedString = base64_decodestring(Base64)
    | where isnotempty(DecodedString)
    | extend
        AccountCustomEntity = Account,
        HostCustomEntity = Computer,
        ProcessCustomEntity = Process
    ),
    (DeviceProcessEvents
    | extend SplitLaunchString = split(ProcessCommandLine, " ")
    | mvexpand SplitLaunchString
    | where SplitLaunchString matches regex "^[A-Za-z0-9+/]{50,}[=]{0,2}$"
    | extend Base64 = tostring(SplitLaunchString)
    | extend DecodedString = base64_decodestring(Base64)
    | where isnotempty(DecodedString)
    | project-rename
        CommandLine = ProcessCommandLine,
        Account = AccountName,
        ParentAccountName = InitiatingProcessAccountName,
        Process = FileName,
        ParentProcess = InitiatingProcessFileName,
        GrandParentProcess = InitiatingProcessParentFileName
    | extend
        AccountCustomEntity = Account,
        HostCustomEntity = DeviceName,
        ProcessCustomEntity = CommandLine
    )
| where not(GrandParentProcess has_any ("SenseIR.exe", "gc_service.exe", "WebexHost.exe", "lmgrd.exe", "zsh", "Code Helper (Renderer)"))
| where not (ParentProcessName has_any ("gc_worker.exe", "CcmExec.exe", "gc_service.exe", "LegacyVSTSPowerShellHost.exe", "CitrixReceiverUpdater.exe"))
| where not (ParentProcess has_any ("atmgr.exe", "gc_worker.exe", "MicrosoftEdgeUpdate.exe", "Adobe Premiere Pro.exe", "Adobe Audition.exe", "webexAppLauncher.exe", "javaws.exe", "Photoshop.exe", "gc_service.exe", "Adobe InDesign 2022", "FluencyDirect.exe", "zsh", "CitrixReceiverUpdater.exe", "konea.exe"))
| where not (Process has_any ("jp2launcher.exe", "Microsoft.Tri.Sensor.Deployment.Deployer.exe", "ksomisc.exe", "wps.exe", "CEPHtmlEngine.exe", "GoogleUpdate.exe", "SecureConnector.exe", "Microsoft.ServiceHub.Controller.exe", "plink.exe", "NwxNlaAgent.exe", "zsh", "CEPHtmlEngine", "UpdateManagementActionExec.exe", "InfraWorksExternalProgressDialog.exe", "PProHeadless", "fs_CalcHash.exe", "manage-bde.exe"))
| where not (CommandLine has "Windows Defender Advanced Threat Protection")
| where not (Process has "git" and (CommandLine has_all("program files", "microsoft visual studio") or FilePath has_all("program files", "microsoft visual studio")))
| where not (CommandLine contains "CgAgACAAIAAgACAAIAAgACAASQBuAHMAdABhAGwAbAAtAE4AdQB0AGEAbgBpAHgAUwBlAHIAdgBpAGMAZQAgAC0ATgBhAG0" or CommandLine contains "IABbAEUAbgB2AGkAcgBvAG4AbQBlAG4AdABdADoAOgBPAFMAVgBlAHIAcwBpAG8AbgAuAFYAZQByAHMAaQBvAG4AIAA" or CommandLine contains "JABDAG8AbgBmAGkAcgBtAFAAcgBlAGYAZQByAGUAbg" or CommandLine contains "JABQAHIAbwBnAHIAZQBzAHMAUAByAGUAZgBlAHIAZQBuAGMAZQA9ACIAUwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZ" or CommandLine contains "JgAgAHsAcABhAHIAYQBtACAAKAAKACAAIAAgACAAWwBQAGEAcgBhAG0AZQB0AGUA" or CommandLine contains "aQBmACgAIAAoAGcAZQB0AC0AZQB4AGUAYwB1AHQA" or CommandLine contains "SQBtAHAAbwByAHQALQBNAG8AZAB1AGwAZQAgAEYAYQBpAGwAbwB2AGUAcgBDAGwAdQBzAHQAZQByAHMAOwAgACQAYwBsAHUAcw" or CommandLine contains "eyJUaXRsZSI6IlVwZGF0ZSBkb25lISIsIk1lc3NhZ2UiOiJDaXRyaXgg")
| where SplitLaunchString !contains "teamfoundation"
| where not (InitiatingProcessCommandLine has_any ("CauScript.cmd", "iTwinSynchronizer.exe", "PAEMigrationAssistant"))
| where not (InitiatingProcessFolderPath has_any ("program files (x86)\\zohomeeting\\agent.exe", "kace", "node.exe", "vstshost"))
| where not (ProcessCustomEntity has_any ("InfraWorksActivityIndicator.exe", "CitrixWorkspaceNotification.exe"))
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = AccountCustomEntity
    }
    entity_type = Host
    field_mappings {
      identifier = FullName
      column_name = HostCustomEntity
    }
    entity_type = Process
    field_mappings {
      identifier = CommandLine
      column_name = ProcessCustomEntity
    }
  }
  tactics = ['CommandAndControl']
  techniques = ['T1001']
  display_name = Base64 Encoding Detected
  description = <<EOT
This rule detects when base64 encoding is used in commands.
EOT
  enabled = True
  create_incident = True
  grouping_configuration {
    enabled = False
    reopen_closed_incident = False
    lookback_duration = PT5H
    entity_matching_method = AllEntities
    group_by_entities = []
    group_by_alert_details = []
    group_by_custom_details = []
  }
  suppression_duration = PT5H
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
