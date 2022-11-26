

resource "azurerm_management_group_policy_assignment" "policy_definition_cmk_assign" {
  name                 = "HMRC RSV CMK"
  display_name         = "HMRC RSV CMK"
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/2e94d99a-8a36-4563-bc77-810d8893b671"
  management_group_id  = local.management_group_id
  location             = local.identity_location
  identity {
    type = "SystemAssigned"
  }
  parameters = file("hmrc-rsv-cmk-assign.json")
}
