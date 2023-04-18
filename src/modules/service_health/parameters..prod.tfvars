# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

action_group_short_name = "mpe_alerting"
action_group_webhooks = {}
action_group_emails = {}

activity_log_alerts = {
    "service-health" = {
      description         = "ServiceHealth global Subscription alerts"
      resource_group_name = var.resource_group_name
      scopes              = [format("/subscriptions/%s", var.subscription_id)]
      criteria = {
        category = "ServiceHealth"
      }
    }

    "security-center" = {
      custom_name         = "${var.workload_name}-global-security-center"
      description         = "Security Center global Subscription alerts"
      resource_group_name = var.resource_group_name
      scopes              = [format("/subscriptions/%s", var.subscription_id)]
      criteria = {
        category = "Security"
        level    = "Error"
      }
    }

    "advisor" = {
      custom_name         = "${var.workload_name}-global-advisor-alerts"
      description         = "Advisor global Subscription alerts"
      resource_group_name = var.resource_group_name
      scopes              = [format("/subscriptions/%s", var.subscription_id)]
      criteria = {
        category = "Recommendation"
        level    = "Informational"
      }
    }

    "managed-disks" = {
      custom_name         = "${var.workload_name}-global-managed-disks-alerts"
      description         = "Azure disks movements alerts"
      resource_group_name = var.resource_group_name
      scopes              = [format("/subscriptions/%s", var.subscription_id)]
      criteria = {
        category      = "Administrative"
        resource_type = "Microsoft.Compute/disks"
        level         = "Informational"
        status        = "Succeeded"
      }
    }
  }
