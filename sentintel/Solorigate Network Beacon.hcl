resource "my_alert_rule" "rule_102" {
  name = "Solorigate Network Beacon"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT6H
  query_period = PT6H
  severity = High
  query = <<EOF
let domains = dynamic(["incomeupdate.com","zupertech.com","databasegalore.com","panhardware.com","avsvmcloud.com","digitalcollege.org","freescanonline.com","deftsecurity.com","thedoccloud.com","virtualdataserver.com","lcomputers.com","webcodez.com","globalnetworkissues.com","kubecloud.com","seobundlekit.com","solartrackingsystem.net","virtualwebdata.com"]);
(union isfuzzy=true
(CommonSecurityLog 
  | parse Message with * '(' DNSName ')' * 
  | where DNSName in~ (domains) or DestinationHostName has_any (domains) or RequestURL has_any(domains)
  | extend AccountCustomEntity = SourceUserID, HostCustomEntity = DeviceName, IPCustomEntity = SourceIP
  ),
(_Im_Dns (domain_has_any=domains)
  | extend DNSName = DnsQuery
  | extend IPCustomEntity = SrcIpAddr
  ),
(VMConnection 
  | parse RemoteDnsCanonicalNames with * '["' DNSName '"]' *
  | where isnotempty(DNSName)
  | where DNSName in~ (domains)
  | extend IPCustomEntity = RemoteIp
  ),
(DeviceNetworkEvents 
  | where isnotempty(RemoteUrl) 
  | where RemoteUrl  has_any (domains)  
  | extend DNSName = RemoteUrl
  | extend IPCustomEntity = RemoteIP 
  | extend HostCustomEntity = DeviceName 
  ),
(AzureDiagnostics 
  | where ResourceType == "AZUREFIREWALLS"
  | where Category == "AzureFirewallApplicationRule"
  | parse msg_s with Protocol 'request from ' SourceHost ':' SourcePort 'to ' DestinationHost ':' DestinationPort '. Action:' Action
  | where isnotempty(DestinationHost)
  | where DestinationHost has_any (domains)  
  | extend DNSName = DestinationHost 
  | extend IPCustomEntity = SourceHost
  ) 
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
  }
  tactics = ['CommandAndControl']
  techniques = ['T1102']
  display_name = Solorigate Network Beacon
  description = <<EOT
Identifies a match across various data feeds for domains IOCs related to the Solorigate incident.
 References: https://blogs.microsoft.com/on-the-issues/2020/12/13/customers-protect-nation-state-cyberattacks/, 
 https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html?1
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
