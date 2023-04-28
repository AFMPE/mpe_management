resource "my_alert_rule" "rule_229" {
  name = "Cisco Umbrella - Hack Tool User-Agent Detected"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT15M
  query_period = PT15M
  severity = Medium
  query = <<EOF
let timeframe = 15m;
let user_agents=dynamic([
                          '(hydra)',
                          ' arachni/',
                          ' BFAC ',
                          ' brutus ',
                          ' cgichk ',
                          'core-project/1.0',
                          ' crimscanner/',
                          'datacha0s',
                          'dirbuster',
                          'domino hunter',
                          'dotdotpwn',
                          'FHScan Core',
                          'floodgate',
                          'get-minimal',
                          'gootkit auto-rooter scanner',
                          'grendel-scan',
                          ' inspath ',
                          'internet ninja',
                          'jaascois',
                          ' zmeu ',
                          'masscan',
                          ' metis ',
                          'morfeus fucking scanner',
                          'n-stealth',
                          'nsauditor',
                          'pmafind',
                          'security scan',
                          'springenwerk',
                          'teh forest lobster',
                          'toata dragostea',
                          ' vega/',
                          'voideye',
                          'webshag',
                          'webvulnscan',
                          ' whcc/',
                          ' Havij',
                          'absinthe',
                          'bsqlbf',
                          'mysqloit',
                          'pangolin',
                          'sql power injector',
                          'sqlmap',
                          'sqlninja',
                          'uil2pn',
                          'ruler',
                          'Mozilla/5.0 (Windows; U; Windows NT 5.1; pt-PT; rv:1.9.1.2) Gecko/20090729 Firefox/3.5.2 (.NET CLR 3.5.30729)'
                          ]);
Cisco_Umbrella
| where EventType == "proxylogs"
| where TimeGenerated > ago(timeframe)
| where HttpUserAgentOriginal has_any (user_agents)
| extend Message = "Hack Tool User Agent"
| project Message, SrcIpAddr, DstIpAddr, UrlOriginal, TimeGenerated, HttpUserAgentOriginal
| extend IPCustomEntity = SrcIpAddr, UrlCustomEntity = UrlOriginal
EOF
  entity_mapping {
    entity_type = URL
    field_mappings {
      identifier = Url
      column_name = UrlCustomEntity
    }
    entity_type = IP
    field_mappings {
      identifier = Address
      column_name = IPCustomEntity
    }
  }
  tactics = ['Execution']
  techniques = ['T1219']
  display_name = Cisco Umbrella - Hack Tool User-Agent Detected
  description = <<EOT
Detects suspicious user agent strings used by known hack tools
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
