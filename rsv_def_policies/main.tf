terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "3.29.1"
    }
  }
}

provider "azurerm" {
  # Configuration options
  skip_provider_registration = true
  features {
  }
}

provider "azurerm" {
  features {}
  alias           = "shared-services"
  subscription_id = "3fdd374f-f524-4b02-99dd-f936dd7e4c0b"
}

locals {
  management_group_id = "/providers/Microsoft.Management/managementGroups/be340a83-4ad7-465a-a206-027fef1da846"
  metadata_content = file("metadata.json")
  identity_location = "uksouth"
}

resource "azurerm_role_assignment" "policy_definition_sami_net_rbac" {
  scope                = local.management_group_id
  role_definition_name = "Contributor"
  principal_id         = azurerm_management_group_policy_assignment.policy_definition_sami_net_assign.identity[0].principal_id
}
# resource "azurerm_role_assignment" "policy_definition_infra_encrypt_rbac" {
#   scope                = local.management_group_id
#   role_definition_name = "Contributor"
#   principal_id         = azurerm_management_group_policy_assignment.policy_definition_infra_encrypt_assign.identity[0].principal_id
# }