#!/bin/bash
#set -x

clear
unset azAdGroupName
unset azAdGroupId
unset azSubscriptionName
unset azSubscriptionId
unset azResourceGroupName
unset azResourceGroupId
unset azNetworkResourceGroupName
unset azNetworkResourceGroupId
unset azSamiName
unset azSamiId
unset vaultMenu

menuSelection=10

########## AZURE RECOVERY SERVICES VAULT ROLE ASSIGNMENT ##############
rsv-role-assignments-add() {
    clear
    echo "
## ----------------------------------------------------------
## Adding Role Assignments to the SAMI for RSV
## ----------------------------------------------------------
"
    read -p "Enter the Azure Subscription Name: " azSubscriptionName
    azSubscriptionId=$(az account show --name ${azSubscriptionName} | jq -r .id)
    [[ -z "${azSubscriptionId}" ]] && read -p "Invalid Subscription - Press [Enter] to return to the menu..." && return 1

    read -p "Enter the Azure Resource Group Name: " azResourceGroupName
    azResourceGroupId=$(az group show --name ${azResourceGroupName} --subscription ${azSubscriptionName} | jq -r .id)
    [[ -z "${azResourceGroupId}" ]] && read -p "Invalid Resource Group - Press [Enter] to return to the menu..." && return 1

    read -p "Enter the Azure Network Resource Group Name: " azNetworkResourceGroupName
    azNetworkResourceGroupId=$(az group show --name ${azNetworkResourceGroupName} --subscription ${azSubscriptionName}  | jq -r .id)
    [[ -z "${azNetworkResourceGroupId}" ]] && read -p "Invalid Network Resource Group - Press [Enter] to return to the menu..." && return 1

    read -p "Enter the SAMI Name: " azSamiName
    azSamiId=$(az resource list --subscription "${azSubscriptionName}" | jq -r ".[] | select (.name == \"${azSamiName}\") | .identity.principalId")
    [[ -z "${azSamiId}" ]] && read -p "Invalid SAMI - Press [Enter] to return to the menu..." && return 1

    echo "-------------------------------------------"
    read -p "Subscription currently set to
Name: ${azSubscriptionName}
Id  : ${azSubscriptionId}
------------------------------------------- 

Check the Subscription details before proceeding - Press [Enter] to continue..."
    clear

    # ----- START AZURE GENERAL RBAC ------
    az role assignment create --assignee "${azSamiId}" --role "Backup Operator" --scope "${azResourceGroupId}" --subscription "${azSubscriptionName}" >/dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        printf "\e[1m%s\e[0m\n%s\n" "SUCCESS: Assignment: Backup Operator Role assigned to Azure Resource Group: ${azResourceGroupName}"

    else
        printf "\e[1m%s\e[0m\n%s\n" "FAILURE: Assignment: Backup Operator Role not assigned to Azure Resource Group: ${azResourceGroupName}"
    fi

    az role assignment create --assignee "${azSamiId}" --role "Backup Contributor" --scope "${azResourceGroupId}" --subscription "${azSubscriptionName}" >/dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        printf "\e[1m%s\e[0m\n%s\n" "SUCCESS: Assignment: Backup Contributor Role assigned to Azure Resource Group: ${azResourceGroupName}"
    else
        printf "\e[1m%s\e[0m\n%s\n" "FAILURE: Assignment: Backup Contributor Role not assigned to Azure Resource Group: ${azResourceGroupName}"
    fi

    az role assignment create --assignee "${azSamiId}" --role "Virtual Machine Contributor" --scope "${azResourceGroupId}" --subscription "${azSubscriptionName}" >/dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        printf "\e[1m%s\e[0m\n%s\n" "SUCCESS: Assignment: Virtual Machine Contributor Role assigned to Azure Resource Group: ${azResourceGroupName}"
    else
        printf "\e[1m%s\e[0m\n%s\n" "FAILURE: Assignment: Virtual Machine Contributor Role not assigned to Azure Resource Group: ${azResourceGroupName}"
    fi

    az role assignment create --assignee "${azSamiId}" --role "Contributor" --scope "${azResourceGroupId}" --subscription "${azSubscriptionName}" >/dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        printf "\e[1m%s\e[0m\n%s\n" "SUCCESS: Assignment: Contributor Role assigned to Azure Resource Group: ${azResourceGroupName}"
    else
        printf "\e[1m%s\e[0m\n%s\n" "FAILURE: Assignment: Contributor Role not assigned to Azure Resource Group: ${azResourceGroupName}"
    fi

    az role assignment create --assignee "${azSamiId}" --role "Storage Account Contributor" --scope "${azResourceGroupId}" --subscription "${azSubscriptionName}" >/dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        printf "\e[1m%s\e[0m\n%s\n" "SUCCESS: Assignment: Storage Account Contributor Role assigned to Azure Resource Group: ${azResourceGroupName}"
    else
        printf "\e[1m%s\e[0m\n%s\n" "FAILURE: Assignment: Storage Account Contributor Role not assigned to Azure Resource Group: ${azResourceGroupName}"
    fi
    az role assignment create --assignee "${azSamiId}" --role "Storage Account Backup Contributor" --scope "${azResourceGroupId}" --subscription "${azSubscriptionName}" >/dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        printf "\e[1m%s\e[0m\n%s\n" "SUCCESS: Assignment: Storage Account Backup Contributor Role assigned to Azure Resource Group: ${azResourceGroupName}"
    else
        printf "\e[1m%s\e[0m\n%s\n" "FAILURE: Assignment: Storage Account Backup Contributor Role not assigned to Azure Resource Group: ${azResourceGroupName}"
    fi

    az role assignment create --assignee "${azSamiId}" --role "Backup Reader" --scope "${azResourceGroupId}" --subscription "${azSubscriptionName}" >/dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        printf "\e[1m%s\e[0m\n%s\n" "SUCCESS: Assignment: Backup Reader Role assigned to Azure Resource Group: ${azResourceGroupName}"
    else
        printf "\e[1m%s\e[0m\n%s\n" "FAILURE: Assignment: Backup Reader Role not assigned to Azure Resource Group: ${azResourceGroupName}"
    fi

    az role assignment create --assignee "${azSamiId}" --role "Network Consumer (Dev)" --scope "${azNetworkResourceGroupId}" --subscription "${azSubscriptionName}" >/dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        printf "\e[1m%s\e[0m\n%s\n" "SUCCESS: Assignment: Network Consumer (Dev) Role assigned to Azure Resource Group: ${azNetworkResourceGroupName}"
    else
        printf "\e[1m%s\e[0m\n%s\n" "FAILURE: Assignment: Network Consumer (Dev) Role not assigned to Azure Resource Group: ${azNetworkResourceGroupName}"
    fi

    read -p "Press [Enter] to continue..."
    return 0

}

########## AZURE BACKUP VAULT ROLE ASSIGNMENT ##############

bsv-role-assignments-add() {
    clear
    echo "
## ----------------------------------------------------------
## Adding Role Assignments to the SAMI for BSV
## ----------------------------------------------------------
"
    read -p "Enter the Azure Subscription Name: " azSubscriptionName
    azSubscriptionId=$(az account show --name ${azSubscriptionName} | jq -r .id)
    [[ -z "${azSubscriptionId}" ]] && read -p "Invalid Subscription - Press [Enter] to return to the menu..." && return 1

    read -p "Enter the Azure Resource Group Name: " azResourceGroupName
    azResourceGroupId=$(az group show --name ${azResourceGroupName} --subscription "${azSubscriptionName}" | jq -r .id)
    [[ -z "${azResourceGroupId}" ]] && read -p "Invalid Resource Group - Press [Enter] to return to the menu..." && return 1

    read -p "Enter the SAMI Name: " azSamiName
    azSamiId=$(az resource list --subscription "${azSubscriptionName}" | jq -r ".[] | select (.name == \"${azSamiName}\") | .identity.principalId")
    [[ -z "${azSamiId}" ]] && read -p "Invalid SAMI - Press [Enter] to return to the menu..." && return 1

    echo "-------------------------------------------"
    read -p "Subscription currently set to
Name: ${azSubscriptionName}
Id  : ${azSubscriptionId}
------------------------------------------- 

Check the Subscription details before proceeding - Press [Enter] to continue..."
    clear

    # ----- START AZURE GENERAL RBAC ------
    az role assignment create --assignee "${azSamiId}" --role "Backup Operator" --scope "${azResourceGroupId}" --subscription "${azSubscriptionName}" >/dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        printf "\e[1m%s\e[0m\n%s\n" "SUCCESS: Assignment: Backup Operator Role assigned to Azure Resource Group: ${azResourceGroupName}"

    else
        printf "\e[1m%s\e[0m\n%s\n" "FAILURE: Assignment: Backup Operator Role not assigned to Azure Resource Group: ${azResourceGroupName}"
    fi

    # ----- END AZURE GENERAL RBAC ------

    # ----- START AZURE DISK RBAC ------
    az role assignment create --assignee "${azSamiId}" --role "Disk Backup Reader" --scope "${azResourceGroupId}" --subscription "${azSubscriptionName}" >/dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        printf "\e[1m%s\e[0m\n%s\n" "SUCCESS: Assignment: Disk Backup Reader Role assigned to Azure Resource Group: ${azResourceGroupName}"
    else
        printf "\e[1m%s\e[0m\n%s\n" "FAILURE: Assignment: Disk Backup Reader Role not assigned to Azure Resource Group: ${azResourceGroupName}"
    fi

    az role assignment create --assignee "${azSamiId}" --role "Disk Snapshot Contributor" --scope "${azResourceGroupId}" --subscription "${azSubscriptionName}" >/dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        printf "\e[1m%s\e[0m\n%s\n" "SUCCESS: Assignment: Disk Snapshot Contributor Role assigned to Azure Resource Group: ${azResourceGroupName}"
    else
        printf "\e[1m%s\e[0m\n%s\n" "FAILURE: Assignment: Disk Snapshot Contributor Role not assigned to Azure Resource Group: ${azResourceGroupName}"
    fi

    az role assignment create --assignee "${azSamiId}" --role "Disk Restore Operator" --scope "${azResourceGroupId}" --subscription "${azSubscriptionName}" >/dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        printf "\e[1m%s\e[0m\n%s\n" "SUCCESS: Assignment: Disk Restore Operator Role assigned to Azure Resource Group: ${azResourceGroupName}"
    else
        printf "\e[1m%s\e[0m\n%s\n" "FAILURE: Assignment: Disk Restore Operator Role not assigned to Azure Resource Group: ${azResourceGroupName}"
    fi
    # ----- END AZURE DISK RBAC ------

    # ----- START AZURE BLOB RBAC ------

    az role assignment create --assignee "${azSamiId}" --role "Storage Account Backup Contributor" --scope "${azResourceGroupId}" --subscription "${azSubscriptionName}" >/dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        printf "\e[1m%s\e[0m\n%s\n" "SUCCESS: Assignment: Storage Account Backup Contributor Role assigned to Azure Resource Group: ${azResourceGroupName}"
    else
        printf "\e[1m%s\e[0m\n%s\n" "FAILURE: Assignment: Storage Account Backup Contributor Role not assigned to Azure Resource Group: ${azResourceGroupName}"
    fi

    # ----- END AZURE BLOB RBAC ------

    # ----- START AZURE POSTGRESQL RBAC ------
    az role assignment create --assignee "${azSamiId}" --role "Reader" --scope "${azResourceGroupId}" --subscription "${azSubscriptionName}" >/dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        printf "\e[1m%s\e[0m\n%s\n" "SUCCESS: Assignment: Reader Role assigned to Azure Resource Group: ${azResourceGroupName}"
    else
        printf "\e[1m%s\e[0m\n%s\n" "FAILURE: Assignment: Reader Role not assigned to Azure Resource Group: ${azResourceGroupName}"
    fi

    az role assignment create --assignee "${azSamiId}" --role "HMRC Custom PostgreSQL Backup Role" --scope "${azResourceGroupId}" --subscription "${azSubscriptionName}" >/dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        printf "\e[1m%s\e[0m\n%s\n" "SUCCESS: Assignment: HMRC Custom PostgreSQL Backup Role assigned to Azure Resource Group: ${azResourceGroupName}"

    else
        printf "\e[1m%s\e[0m\n%s\n" "FAILURE: Assignment: HMRC Custom PostgreSQL Backup Role not assigned to Azure Resource Group: ${azResourceGroupName}"
    fi
    read -p "Press [Enter] to continue..."
    return 0
    # ----- END AZURE POSTGRESQL RBAC ------
}

role-add-menu() {
    clear
    echo "
--------------------------------
   BSV & RSV Add Roles Menu
--------------------------------
1) Assign RSV Roles
2) Assign BSV Roles
0) Exit
    "
    read -p "Enter a menu selection: " azMenu
    echo
    case ${azMenu} in
    1) rsv-role-assignments-add ;;
    2) bsv-role-assignments-add ;;
    0) exit ;;
    *)
        echo
        read -p "Please enter a valid selection or press 0 to exit"
        role-add-menu
        ;;
    esac
}

# Main
until [[ menuSelection -eq 0 ]]; do
    role-add-menu
done
