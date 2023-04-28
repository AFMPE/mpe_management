resource "my_alert_rule" "rule_352" {
  name = "Solorigate Domains Found in VM Insights"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT1H
  query_period = PT1H
  severity = High
  query = <<EOF
let domains = dynamic(["incomeupdate.com","zupertech.com","databasegalore.com","panhardware.com","avsvmcloud.com","digitalcollege.org","freescanonline.com","deftsecurity.com","thedoccloud.com","virtualdataserver.com","lcomputers.com","webcodez.com","globalnetworkissues.com","kubecloud.com","seobundlekit.com","solartrackingsystem.net","virtualwebdata.com"]);
let timeframe = 1h;
let connections = VMConnection 
    | where TimeGenerated >= ago(timeframe)
    | extend DNSName = set_union(todynamic(RemoteDnsCanonicalNames),todynamic(RemoteDnsQuestions))
    | mv-expand DNSName
    | where isnotempty(DNSName)
    | where DNSName has_any (domains)
    | extend IPCustomEntity = RemoteIp
    | summarize TimeGenerated = arg_min(TimeGenerated, *), requests = count() by IPCustomEntity, DNSName = tostring(DNSName), AgentId, Machine, Process;
let processes = VMProcess
    | where TimeGenerated >= ago(timeframe)
    | project AgentId, Machine, Process, UserName, UserDomain, ExecutablePath, CommandLine, FirstPid
    | extend exePathArr = split(ExecutablePath, "\\")
    | extend DirectoryName = array_strcat(array_slice(exePathArr, 0, array_length(exePathArr) - 2), "\\")
    | extend Filename = array_strcat(array_slice(exePathArr, array_length(exePathArr) - 1, array_length(exePathArr)), "\\")
    | project-away exePathArr;
let computers = VMComputer
    | where TimeGenerated >= ago(timeframe)
    | project HostCustomEntity = HostName, AzureResourceId = _ResourceId, AgentId, Machine;
connections | join kind = inner (processes) on AgentId, Machine, Process
            | join kind = inner (computers) on AgentId, Machine
EOF
  entity_mapping {
    entity_type = Host
    field_mappings {
      identifier = HostName
      column_name = HostCustomEntity
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPCustomEntity
    }
    entity_type = DNS
    field_mappings {
      identifier = DomainName
      column_name = DNSName
    }
    entity_type = Process
    field_mappings {
      identifier = ProcessId
      column_name = FirstPid
      identifier = CommandLine
      column_name = CommandLine
    }
    entity_type = File
    field_mappings {
      identifier = Directory
      column_name = DirectoryName
      identifier = Name
      column_name = Filename
    }
  }
  tactics = ['CommandAndControl']
  techniques = ['T1102']
  display_name = Solorigate Domains Found in VM Insights
  description = <<EOT
Identifies connections to Solorigate-related DNS records based on VM insights data
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
