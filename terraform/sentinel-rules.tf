# =============================================================
# Sentinel analytics rules (the six detection rules)
#
# REFERENCE IaC — NOT re-applied through Terraform. These mirror
# the rules authored interactively in the portal (README section 4).
# Entity-mapping syntax and exact query strings are the parts most
# likely to need reconciling on a real `terraform plan`.
#
# Depends on the workspace data source in main.tf.
# One rule (Firewall Disabled) is included for completeness but is
# the documented false-negative from README section 4 — the query
# below is the CORRECTED version (token-based `has`, no user filter).
# =============================================================

locals {
  rule_frequency = "PT5M" # run every 5 minutes
  rule_period    = "PT5H" # look back 5 hours
}

# ---- 1. RDP Brute Force (T1110) -------------------------------
resource "azurerm_sentinel_alert_rule_scheduled" "rdp_brute_force" {
  name                       = "Honeypot-RDP-Brute-Force"
  log_analytics_workspace_id = data.azurerm_log_analytics_workspace.ws.id
  display_name               = "Honeypot - RDP Brute Force (4625)"
  severity                   = "Medium"
  enabled                    = true
  query_frequency            = local.rule_frequency
  query_period               = local.rule_period
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1110"]

  query = <<-QUERY
    SecurityEvent
    | where EventID == 4625
    | summarize FailedAttempts = count() by IpAddress, Computer, Account
    | where FailedAttempts >= 3
  QUERY

  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "IpAddress"
    }
  }
  entity_mapping {
    entity_type = "Host"
    field_mapping {
      identifier  = "HostName"
      column_name = "Computer"
    }
  }
  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "Name"
      column_name = "Account"
    }
  }

  incident_configuration {
    create_incident = true
  }
}

# ---- 2. New Local User (T1136) --------------------------------
resource "azurerm_sentinel_alert_rule_scheduled" "new_local_user" {
  name                       = "Honeypot-New-Local-User"
  log_analytics_workspace_id = data.azurerm_log_analytics_workspace.ws.id
  display_name               = "Honeypot - New Local User Created (4720)"
  severity                   = "Medium"
  enabled                    = true
  query_frequency            = local.rule_frequency
  query_period               = local.rule_period
  tactics                    = ["Persistence"]
  techniques                 = ["T1136"]

  query = <<-QUERY
    SecurityEvent
    | where EventID == 4720
    | project TimeGenerated, Activity, TargetAccount, SubjectAccount, Computer
  QUERY

  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "Name"
      column_name = "TargetAccount"
    }
  }
  entity_mapping {
    entity_type = "Host"
    field_mapping {
      identifier  = "HostName"
      column_name = "Computer"
    }
  }

  incident_configuration {
    create_incident = true
  }
}

# ---- 3. User Added to Administrators (T1098) ------------------
resource "azurerm_sentinel_alert_rule_scheduled" "user_added_admin" {
  name                       = "Honeypot-User-Added-Admin"
  log_analytics_workspace_id = data.azurerm_log_analytics_workspace.ws.id
  display_name               = "Honeypot - User Added to Administrators (4732)"
  severity                   = "High"
  enabled                    = true
  query_frequency            = local.rule_frequency
  query_period               = local.rule_period
  tactics                    = ["PrivilegeEscalation"]
  techniques                 = ["T1098"]

  query = <<-QUERY
    SecurityEvent
    | where EventID == 4732
    | where TargetUserName has_any ("Administrators", "Administratoren")
    | project TimeGenerated, Activity, MemberName, TargetUserName, SubjectAccount, Computer
  QUERY

  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "Name"
      column_name = "MemberName"
    }
  }
  entity_mapping {
    entity_type = "Host"
    field_mapping {
      identifier  = "HostName"
      column_name = "Computer"
    }
  }

  incident_configuration {
    create_incident = true
  }
}

# ---- 4. Scheduled Task Created (T1053) ------------------------
# NOTE: this is the "too broad" rule from README section 4 — it fires
# on every 4698, including legitimate Windows tasks (alert fatigue).
# Kept as-is to document the finding; a tuned version would narrow to
# tasks running as SYSTEM that launch powershell/cmd, or unusual names.
resource "azurerm_sentinel_alert_rule_scheduled" "scheduled_task" {
  name                       = "Honeypot-Scheduled-Task"
  log_analytics_workspace_id = data.azurerm_log_analytics_workspace.ws.id
  display_name               = "Honeypot - Scheduled Task Created (4698)"
  severity                   = "Medium"
  enabled                    = true
  query_frequency            = local.rule_frequency
  query_period               = local.rule_period
  tactics                    = ["Persistence"]
  techniques                 = ["T1053"]

  query = <<-QUERY
    SecurityEvent
    | where EventID == 4698
    | project TimeGenerated, Activity, SubjectAccount, Computer
  QUERY

  entity_mapping {
    entity_type = "Host"
    field_mapping {
      identifier  = "HostName"
      column_name = "Computer"
    }
  }

  incident_configuration {
    create_incident = true
  }
}

# ---- 5. Suspicious Egress Download (T1105) --------------------
# NOTE: noisy by design — any outbound 443/80 fires. Acceptable on a
# honeypot (almost no legitimate egress); on a real system this needs
# an allowlist of known destinations.
resource "azurerm_sentinel_alert_rule_scheduled" "egress_download" {
  name                       = "Honeypot-Egress-Download"
  log_analytics_workspace_id = data.azurerm_log_analytics_workspace.ws.id
  display_name               = "Honeypot - Suspicious Egress Download (Sysmon 3)"
  severity                   = "Medium"
  enabled                    = true
  query_frequency            = local.rule_frequency
  query_period               = local.rule_period
  tactics                    = ["CommandAndControl"]
  techniques                 = ["T1105"]

  query = <<-QUERY
    Event
    | where Source == "Microsoft-Windows-Sysmon" and EventID == 3
    | extend DestPort = extract(@"DestinationPort: ([0-9]+)", 1, RenderedDescription)
    | extend DestIP = extract(@"DestinationIp: ([^\s]+)", 1, RenderedDescription)
    | where DestPort in ("443", "80")
    | where not(DestIP startswith "172.16" or DestIP startswith "10." or DestIP startswith "::1" or DestIP == "127.0.0.1")
    | project TimeGenerated, DestIP, DestPort, Computer
  QUERY

  entity_mapping {
    entity_type = "Host"
    field_mapping {
      identifier  = "HostName"
      column_name = "Computer"
    }
  }
  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "DestIP"
    }
  }

  incident_configuration {
    create_incident = true
  }
}

# ---- 6. Firewall Disabled (T1562) -----------------------------
# The README section 4 false-negative. This is the CORRECTED query:
# token-based `has "advfirewall"` (not the phrase "netsh advfirewall"),
# and no user filter (actions via run-command execute as SYSTEM).
resource "azurerm_sentinel_alert_rule_scheduled" "firewall_disabled" {
  name                       = "Honeypot-Firewall-Disabled"
  log_analytics_workspace_id = data.azurerm_log_analytics_workspace.ws.id
  display_name               = "Honeypot - Firewall Disabled (netsh/4950)"
  severity                   = "High"
  enabled                    = true
  query_frequency            = local.rule_frequency
  query_period               = local.rule_period
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1562"]

  query = <<-QUERY
    Event
    | where Source == "Microsoft-Windows-Sysmon" and EventID == 1
    | where RenderedDescription has "advfirewall" or RenderedDescription has "Set-NetFirewallProfile"
    | extend CommandLine = extract(@"CommandLine: (.*?) CurrentDirectory", 1, RenderedDescription)
    | project TimeGenerated, CommandLine, Computer
  QUERY

  entity_mapping {
    entity_type = "Host"
    field_mapping {
      identifier  = "HostName"
      column_name = "Computer"
    }
  }

  incident_configuration {
    create_incident = true
  }
}
