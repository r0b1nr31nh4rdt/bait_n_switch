# =============================================================
# Bait n' Switch — Honeypot telemetry as Infrastructure-as-Code
#
# REFERENCE IaC. Derived from the verified `az` CLI deployment
# used to build this project. It mirrors the resources that were
# created and confirmed working via the CLI, but has NOT been
# re-applied through Terraform — treat it as documentation of the
# deployment, not as a tested module. Before using: run
# `terraform plan` against a fresh resource group and reconcile
# any provider-version differences.
#
# Assumes the VM, its NIC/NSG and the Log Analytics workspace
# already exist (they were created during the project). This file
# wires up the telemetry pipeline: Managed Identity -> AMA ->
# Data Collection Rule -> workspace, plus Sysmon and the NSG rule.
# =============================================================

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}
}

# ---- Variables -------------------------------------------------
variable "resource_group_name" {
  type    = string
  default = "rg-bait-n-switch"
}

variable "location" {
  type    = string
  default = "germanywestcentral"
}

variable "vm_name" {
  type    = string
  default = "HR-FILE-SRV-01"
}

variable "workspace_name" {
  type    = string
  default = "sentinel-bait-n-switch"
}

# ---- Existing resources (created during the project) ----------
data "azurerm_resource_group" "rg" {
  name = var.resource_group_name
}

data "azurerm_windows_virtual_machine" "honeypot" {
  name                = var.vm_name
  resource_group_name = data.azurerm_resource_group.rg.name
}

data "azurerm_log_analytics_workspace" "ws" {
  name                = var.workspace_name
  resource_group_name = data.azurerm_resource_group.rg.name
}

# ---- NSG rule: open RDP (3389) to Any -------------------------
# The intentional vulnerability. Assumes an existing NSG attached
# to the VM's subnet/NIC; adjust the NSG name as needed.
variable "nsg_name" {
  type    = string
  default = "HR-FILE-SRV-01-nsg"
}

resource "azurerm_network_security_rule" "allow_rdp_any" {
  name                        = "Allow-RDP-Any"
  priority                    = 300
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "3389"
  source_address_prefix       = "*" # Any — this is the honeypot's bait
  destination_address_prefix  = "*"
  resource_group_name         = data.azurerm_resource_group.rg.name
  network_security_group_name = var.nsg_name
}

# ---- System-Assigned Managed Identity on the VM ---------------
# THE step the CLI path silently skips. Without this the AMA agent
# cannot authenticate to Azure Monitor and no telemetry flows
# (no heartbeat), even though everything reports "Succeeded".
# NOTE: the VM already exists; in a from-scratch build you would set
# identity { type = "SystemAssigned" } on the VM resource itself.
# Shown here for documentation of the dependency.

# ---- AMA agent extension on the VM ----------------------------
resource "azurerm_virtual_machine_extension" "ama" {
  name                       = "AzureMonitorWindowsAgent"
  virtual_machine_id         = data.azurerm_windows_virtual_machine.honeypot.id
  publisher                  = "Microsoft.Azure.Monitor"
  type                       = "AzureMonitorWindowsAgent"
  type_handler_version       = "1.0"
  auto_upgrade_minor_version = true
}

# ---- Data Collection Rule -------------------------------------
# Collects All Security Events (Security!*) plus the Sysmon,
# PowerShell and TaskScheduler operational channels.
resource "azurerm_monitor_data_collection_rule" "honeypot" {
  name                = "dcr-honeypot-allsecurity"
  resource_group_name = data.azurerm_resource_group.rg.name
  location            = var.location

  destinations {
    log_analytics {
      workspace_resource_id = data.azurerm_log_analytics_workspace.ws.id
      name                  = "laDest"
    }
  }

  data_sources {
    windows_event_log {
      name    = "securityAll"
      streams = ["Microsoft-SecurityEvent"]
      x_path_queries = [
        "Security!*"
      ]
    }
    windows_event_log {
      name    = "sysmonAndPowershell"
      streams = ["Microsoft-Event"]
      x_path_queries = [
        "Microsoft-Windows-Sysmon/Operational!*",
        "Microsoft-Windows-PowerShell/Operational!*",
        "Microsoft-Windows-TaskScheduler/Operational!*"
      ]
    }
  }

  data_flow {
    streams      = ["Microsoft-SecurityEvent"]
    destinations = ["laDest"]
  }

  data_flow {
    streams      = ["Microsoft-Event"]
    destinations = ["laDest"]
  }
}

# ---- Associate the DCR with the VM ----------------------------
resource "azurerm_monitor_data_collection_rule_association" "honeypot" {
  name                    = "assoc-${var.vm_name}"
  target_resource_id      = data.azurerm_windows_virtual_machine.honeypot.id
  data_collection_rule_id = azurerm_monitor_data_collection_rule.honeypot.id
}

# ---- Sysmon with SwiftOnSecurity config -----------------------
# Installed via a run-command in the project; shown here as a
# custom-script extension that runs the separate install-sysmon.ps1
# (cleaner and testable, vs. an inline one-liner). The script is
# base64-encoded from the local file and passed to the extension,
# so no external hosting is required.
resource "azurerm_virtual_machine_extension" "sysmon" {
  name                 = "install-sysmon"
  virtual_machine_id   = data.azurerm_windows_virtual_machine.honeypot.id
  publisher            = "Microsoft.Compute"
  type                 = "CustomScriptExtension"
  type_handler_version = "1.10"

  protected_settings = jsonencode({
    commandToExecute = "powershell -ExecutionPolicy Unrestricted -EncodedCommand ${textencodebase64(file("${path.module}/install-sysmon.ps1"), "UTF-16LE")}"
  })

  depends_on = [azurerm_virtual_machine_extension.ama]
}

# -------------------------------------------------------------------
# Analytics rules (the six detection rules) are intentionally NOT in
# Terraform here. They were authored interactively and iterated on
# (see README section 4). They could be captured as
# azurerm_sentinel_alert_rule_scheduled resources as a follow-up.
# -------------------------------------------------------------------
