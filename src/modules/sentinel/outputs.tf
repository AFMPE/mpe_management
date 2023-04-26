# Output Log Workspace Analytics Onboarding ID
output "log_analytics_onboarding_id" {
    value = azurerm_sentinel_log_analytics_workspace_onboarding.log_ws_onboard.id
}

