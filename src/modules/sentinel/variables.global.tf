# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

/*
  PARAMETERS
  Here are all the variables a user can override.
*/
variable "log_analytics_ws_id" {
    description = "Log Analytics workspace id for onboarding"
    type = string
    default = ""
}