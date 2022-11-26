

resource "azurerm_policy_definition" "policy_definition_infra_encrypt" {
  name                = "HMRC RSV Infra Encrypt"
  display_name        = "HMRC RSV Infra Encrypt"
  policy_type         = "Custom"
  mode                = "All"
  management_group_id = local.management_group_id
  metadata            = local.metadata_content
  policy_rule         = file("hmrc-rsv-infra-encrypt.json")
  parameters          = file("hmrc-rsv-infra-encrypt-param.json")
}

resource "azurerm_management_group_policy_assignment" "policy_definition_infra_encrypt_assign" {
  name                 = azurerm_policy_definition.policy_definition_infra_encrypt.display_name
  policy_definition_id = azurerm_policy_definition.policy_definition_infra_encrypt.id
  management_group_id  = local.management_group_id
  location             = local.identity_location
  identity {
    type = "SystemAssigned"
  }
  parameters = file("hmrc-rsv-infra-encrypt-assign.json")
}

