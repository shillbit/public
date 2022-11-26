

resource "azurerm_policy_definition" "policy_definition_sap_hana" {
  name                = "HMRC RSV SAP HANA DB"
  display_name        = "HMRC RSV SAP HANA DB"
  policy_type         = "Custom"
  mode                = "All"
  management_group_id = local.management_group_id
  metadata            = local.metadata_content
  policy_rule         = file("hmrc-rsv-sap-hana.json")
  parameters          = file("hmrc-rsv-sap-hana-param.json")
}

resource "azurerm_management_group_policy_assignment" "policy_definition_sap_hana_assign" {
  name                 = azurerm_policy_definition.policy_definition_sap_hana.display_name
  policy_definition_id = azurerm_policy_definition.policy_definition_sap_hana.id
  management_group_id  = local.management_group_id
  location             = local.identity_location
  identity {
    type = "SystemAssigned"
  }
  parameters = file("hmrc-rsv-sap-hana-assign.json")
}

