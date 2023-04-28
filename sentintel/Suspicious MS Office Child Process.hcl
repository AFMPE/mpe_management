resource "my_alert_rule" "rule_308" {
  name = "Suspicious MS Office Child Process"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = Low
  query = <<EOF
let ProcessFileName = dynamic(["eqnedt32.exe", "excel.exe", "fltldr.exe", "msaccess.exe", "mspub.exe", "powerpnt.exe", "winword.exe"]);
let IOC = dynamic(["Microsoft.Workflow.Compiler.exe", "arp.exe", "atbroker.exe", "bginfo.exe", "bitsadmin.exe", "cdb.exe", "certutil.exe", "cmd.exe", "cmstp.exe", "cscript.exe", "csi.exe", "dnx.exe", "dsget.exe", "dsquery.exe", "forfiles.exe", "fsi.exe", "ftp.exe", "gpresult.exe", "hostname.exe", "ieexec.exe", "iexpress.exe", "installutil.exe", "ipconfig.exe", "mshta.exe", "msxsl.exe", "nbtstat.exe", "net.exe", "net1.exe", "netsh.exe", "netstat.exe", "nltest.exe", "odbcconf.exe", "ping.exe", "powershell.exe", "pwsh.exe", "process.exe", "quser.exe", "qwinsta.exe", "rcsi.exe", "reg.exe", "regasm.exe", "regsvcs.exe", "regsvr32.exe", "sc.exe", "schtasks.exe", "systeminfo.exe", "tasklist.exe", "tracert.exe", "whoami.exe", "wmic.exe", "wscript.exe", "xwizard.exe"]);
union
(
DeviceProcessEvents
| where InitiatingProcessFileName in (ProcessFileName) and ProcessCommandLine in (IOC)
| extend AccountCustomEntity = AccountName, HostCustomEntity = DeviceName
),
(
SecurityEvent 
| where EventID == 4688 and (ParentProcessName in (ProcessFileName) and Process in (IOC))
| extend AccountCustomEntity = Account, HostCustomEntity = Computer
)
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
  }
  tactics = ['Persistence']
  techniques = ['T1137']
  display_name = Suspicious MS Office Child Process
  description = <<EOT
'Identifies suspicious child processes of frequently targeted Microsoft Office applications (Word, PowerPoint, Excel). These child processes are often launched during exploitation of Office applications or from documents with malicious macros.'

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
