

resource "azurerm_policy_definition" "policy_definition_law" {
  name                = "HMRC RSV Diagnostic Logs"
  display_name        = "HMRC RSV Diagnostic Logs"
  policy_type         = "Custom"
  mode                = "All"
  management_group_id = local.management_group_id
  metadata            = local.metadata_content
  policy_rule         = file("hmrc-rsv-law.json")
  parameters          = file("hmrc-rsv-law-param.json")
}

resource "azurerm_management_group_policy_assignment" "policy_definition_law_assign" {
  name                 = azurerm_policy_definition.policy_definition_law.display_name
  policy_definition_id = azurerm_policy_definition.policy_definition_law.id
  management_group_id  = local.management_group_id
  location             = local.identity_location
  identity {
    type = "SystemAssigned"
  }
  parameters = file("hmrc-rsv-law-assign.json")
}

