resource "my_alert_rule" "rule_162" {
  name = "DNS events related to mining pools"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = P1D
  query_period = P1D
  severity = Low
  query = <<EOF
DnsEvents
| where Name contains "."
| where Name has_any ("monerohash.com", "do-dear.com", "xmrminerpro.com", "secumine.net", "xmrpool.com", "minexmr.org", "hashanywhere.com", 
"xmrget.com", "mininglottery.eu", "minergate.com", "moriaxmr.com", "multipooler.com", "moneropools.com", "xmrpool.eu", "coolmining.club", 
"supportxmr.com", "minexmr.com", "hashvault.pro", "xmrpool.net", "crypto-pool.fr", "xmr.pt", "miner.rocks", "walpool.com", "herominers.com", 
"gntl.co.uk", "semipool.com", "coinfoundry.org", "cryptoknight.cc", "fairhash.org", "baikalmine.com", "tubepool.xyz", "fairpool.xyz", "asiapool.io", 
"coinpoolit.webhop.me", "nanopool.org", "moneropool.com", "miner.center", "prohash.net", "poolto.be", "cryptoescrow.eu", "monerominers.net", "cryptonotepool.org", 
"extrmepool.org", "webcoin.me", "kippo.eu", "hashinvest.ws", "monero.farm", "supportxmr.com", "xmrpool.eu", "linux-repository-updates.com", "1gh.com", 
"dwarfpool.com", "hash-to-coins.com", "hashvault.pro", "pool-proxy.com", "hashfor.cash", "fairpool.cloud", "litecoinpool.org", "mineshaft.ml", "abcxyz.stream", 
"moneropool.ru", "cryptonotepool.org.uk", "extremepool.org", "extremehash.com", "hashinvest.net", "unipool.pro", "crypto-pools.org", "monero.net", 
"backup-pool.com", "mooo.com", "freeyy.me", "cryptonight.net", "shscrypto.net")
| extend timestamp = TimeGenerated, IPCustomEntity = ClientIP, HostCustomEntity = Computer
EOF
  entity_mapping {
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
  }
  tactics = ['Impact']
  techniques = ['T1496']
  display_name = DNS events related to mining pools
  description = <<EOT
Identifies IP addresses that may be performing DNS lookups associated with common currency mining pools.
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
