resource "my_alert_rule" "rule_50" {
  name = "Suspicious PDF Reader Child Process"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT5M
  query_period = PT5M
  severity = Low
  query = <<EOF
let ProcessFileName = dynamic(["AcroRd32.exe", "Acrobat.exe", "FoxitPhantomPDF.exe", "FoxitReader.exe"]);
let IOC = dynamic(["arp.exe" , "dsquery.exe" , "dsget.exe" , "gpresult.exe" , "hostname.exe" , "ipconfig.exe" , "nbtstat.exe" , "net.exe" , "net1.exe" , "netsh.exe" , "netstat.exe" , "nltest.exe" , "ping.exe" , "qprocess.exe" , "quser.exe" , "qwinsta.exe" , "reg.exe" , "sc.exe" , "systeminfo.exe" , "tasklist.exe" , "tracert.exe" , "whoami.exe" , "bginfo.exe" , "cdb.exe" , "cmstp.exe" , "csi.exe" , "dnx.exe" , "fsi.exe" , "ieexec.exe" , "iexpress.exe" , "installutil.exe" , "Microsoft.Workflow.Compiler.exe" , "msbuild.exe" , "mshta.exe" , "msxsl.exe" , "odbcconf.exe" , "rcsi.exe" , "regsvr32.exe" , "xwizard.exe" , "atbroker.exe" , "forfiles.exe" , "schtasks.exe" , "regasm.exe" , "regsvcs.exe" , "cmd.exe" , "cscript.exe" , "powershell.exe" , "pwsh.exe" , "wmic.exe" , "wscript.exe" , "bitsadmin.exe" , "certutil.exe" , "ftp.exe"]);
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
  tactics = ['Execution']
  techniques = ['T1059']
  display_name = Suspicious PDF Reader Child Process
  description = <<EOT
'Identifies suspicious child processes of PDF reader applications. These child processes are often launched via exploitation of PDF applications or social engineering.'

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
