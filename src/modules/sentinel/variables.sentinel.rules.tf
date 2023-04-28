# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

/*
  PARAMETERS
  Here are all the variables a user can override.
*/

#################################
# Global Sentinel Configuration
#################################

variable "sentinel_rule_alerts" {
  description = "A map of alerts to be created."
  type = map(object({
    query_frequency      = string
    query_period         = string
    severity             = string
    query                = string

   entity_mappings = list(object({
      entity_type = string
      field_name = string
      identifier     = string
    }))
    
    tactics = list(string)
    techniques           = list(string)

    display_name         = string
    description          = string
    enabled              = bool
    
    #Incident Configuration Block
    create_incident      = bool
    # Grouping Block in incident_configuration block
    grouping_configuration = map(object({
      enabled = bool
      lookback_duration       = string
      reopen_closed_incidents = bool
      entity_matching_method  = string
      group_by_entities       = list(string)
      group_by_alert_details  = list(string)
      group_by_custom_details = list(string)
    }))

    suppression_duration = string
    suppression_enabled  = bool
    event_grouping = map(string)
  }))
  default = {}
}


############################
# Sentinel Configuration  ##
############################

/* sentinel_rule_alerts = {
  "malicious_web_request" = {
    name                 = "A potentially malicious web request was executed against a web server"
    display_name         = "A potentially malicious web request was executed against a web server"
    description          = <<EOT
        Detects unobstructed Web Application Firewall (WAF) activity in sessions where the WAF blocked incoming requests by computing the 
        ratio between blocked requests and unobstructed WAF requests in these sessions (BlockvsSuccessRatio metric). A high ratio value for 
        a given client IP and hostname calls for further investigation of the WAF data in that session, due to the significantly high number 
        of blocked requests and a few unobstructed logs which may be malicious but have passed undetected through the WAF. The successCode 
        variable defines what the detection thinks is a successful status code, and should be altered to fit the environment.
        EOT
    enabled              = false
    severity             = "Medium"
    query                = <<EOF
        let queryperiod = 1d;
        let mode = 'Blocked';
        let successCode = dynamic(['200', '101','204', '400','504','304','401','500']);
        let sessionBin = 30m;
        AzureDiagnostics
        | where TimeGenerated > ago(queryperiod)
        | where Category == 'ApplicationGatewayFirewallLog' and action_s == mode
        | sort by hostname_s asc, clientIp_s asc, TimeGenerated asc
        | extend SessionBlockedStarted = row_window_session(TimeGenerated, queryperiod, 10m, ((clientIp_s != prev(clientIp_s)) or (hostname_s != prev(hostname_s))))
        | summarize SessionBlockedEnded = max(TimeGenerated), SessionBlockedCount = count() by hostname_s, clientIp_s, SessionBlockedStarted
        | extend TimeKey = range(bin(SessionBlockedStarted, sessionBin), bin(SessionBlockedEnded, sessionBin), sessionBin)
        | mv-expand TimeKey to typeof(datetime)
        | join kind = inner(
            AzureDiagnostics
            | where TimeGenerated > ago(queryperiod)
            | where Category == 'ApplicationGatewayAccessLog' and (isempty(httpStatus_d) or httpStatus_d in (successCode))
            | extend TimeKey = bin(TimeGenerated, sessionBin)
        ) on TimeKey, $left.hostname_s == $right.host_s, $left.clientIp_s == $right.clientIP_s
        | where TimeGenerated between (SessionBlockedStarted..SessionBlockedEnded)
        | extend
            originalRequestUriWithArgs_s = column_ifexists("originalRequestUriWithArgs_s", ""),
            serverStatus_s = column_ifexists("serverStatus_s", "")
        | summarize
            SuccessfulAccessCount = count(),
            UserAgents = make_set(userAgent_s, 250),
            RequestURIs = make_set(requestUri_s, 250),
            OriginalRequestURIs = make_set(originalRequestUriWithArgs_s, 250),
            SuccessCodes = make_set(httpStatus_d, 250),
            SuccessCodes_BackendServer = make_set(serverStatus_s, 250),
            take_any(SessionBlockedEnded, SessionBlockedCount)
            by hostname_s, clientIp_s, SessionBlockedStarted
        | where SessionBlockedCount > SuccessfulAccessCount
        | extend timestamp = SessionBlockedStarted, IPCustomEntity = clientIp_s
        | extend BlockvsSuccessRatio = SessionBlockedCount/toreal(SuccessfulAccessCount)
        | sort by BlockvsSuccessRatio desc, timestamp asc
        | project-reorder SessionBlockedStarted, SessionBlockedEnded, hostname_s, clientIp_s, SessionBlockedCount, SuccessfulAccessCount, BlockvsSuccessRatio, SuccessCodes, RequestURIs, OriginalRequestURIs, UserAgents
        EOF
    query_frequency      = "P1D"
    query_period         = "P1D"
    action               = "Log"
    suppression_duration = "PT5H"
    suppression_enabled  = false
    grouping             = false
    create_incident      = true
    incident_configuration = {
      reopen_closed_incident  = false
      lookback_duration       = "P1D"
      entity_matching_method  = "AllEntities"
      group_by_entities       = []
      group_by_alert_details  = ["None"]
      group_by_custom_details = ["None"]
    }
    entity_mappings = [
      {
        entity_type = "IP"
        field_mappings = [
          {
            identifier = "IPAddress"
            field_name = "IPCustomEntity"
          }
        ]
      }
    ]
    tactics    = ["InitialAccess"]
    techniques = ["T1190"]
    trigger_operator = ""
    trigger_threshold = 0
  }
}
 */