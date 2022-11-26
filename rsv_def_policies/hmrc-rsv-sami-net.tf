

resource "azurerm_policy_definition" "policy_definition_sami_net" {
  name                = "HMRC RSV SAMI - Network"
  display_name        = "HMRC RSV SAMI - Network"
  policy_type         = "Custom"
  mode                = "All"
  management_group_id = local.management_group_id
  metadata            = local.metadata_content
  policy_rule         = file("hmrc-rsv-sami-net.json")
  parameters          = file("hmrc-rsv-sami-net-param.json")
}

resource "azurerm_management_group_policy_assignment" "policy_definition_sami_net_assign" {
  name                 = azurerm_policy_definition.policy_definition_sami_net.display_name
  policy_definition_id = azurerm_policy_definition.policy_definition_sami_net.id
  management_group_id  = local.management_group_id
  location             = local.identity_location
  identity {
    type = "SystemAssigned"
  }
  parameters = file("hmrc-rsv-sami-net-assign.json")
}

