<#PSScriptInfo

.VERSION 
    2.2

.DATE LAST UPDATED
    06/09/2020
    07/13/2021
	08/05/2021
    07/12/2022

.AUTHOR 
    prmarri

.COMPANYNAME 
    Microsoft Corporation

.COPYRIGHT 
    Copyright (C) Microsoft Corporation. All rights reserved.

.TAGS
    WindowsDefender,DLP

.LICENSEURI 
    //*********************************************************
    //
    //    Copyright (c) Microsoft Corporation. All rights reserved.
    //    This code is licensed under the Microsoft Public License.
    //    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
    //    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
    //    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
    //    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
    //
    //*********************************************************

.PROJECTURI 

.ICONURI 

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS 

.EXTERNALSCRIPTDEPENDENCIES 

.RELEASENOTES


#>

<# 

.DESCRIPTION
   DLP Self Diagnosing Tool

#> 



### LOGGING RELATED. 
[string]$global:DLP_DIAGNOSE_LOGPATH = join-path ($env:systemdrive) DLPDiagnoseLogs
[string]$global:DLP_DIAGNOSE_FILENAME = "DLPDiagnosing.log"
[string]$global:LogFileName = ""
[string]$global:DLPBackPortFile = "FeatureToastDlpImg.png"
[int]$global:OSBuildNum = 0

[string]$global:CurEngVer = ""
[string]$global:CurMoCAMPVer=""
[string]$global:MIN_MOCAMPVER_NEEDED = "4.18.2005.3"
[string]$global:MIN_ENGINEVER_NEEDED = "1.1.17046.0"


[boolean]$global:bDLPMinReqOS = $true


############################################################################################

### FUNCTION: WRITE CONSOLE OUTPUT IN COLOR

############################################################################################

function Write-ColorOutput($foregroundColor)
{

    LogToFile $args
    # save the current color
    $fc = $host.UI.RawUI.ForegroundColor

    # set the new color
    $host.UI.RawUI.ForegroundColor = $foregroundColor

    # output
    if ($args)
    {
        Write-Output $args
    }
    else
    {
        $input | Write-Output
    }

    # restore the original color
    $host.UI.RawUI.ForegroundColor = $fc
}




############################################################################################

# GENERIC FUNCTION: TO LOG MESSAGES TO A CONFIGURED LOG FILE

############################################################################################

function LogToFile
{
    param($message);

    if (($global:LogFileName -ne "") -and (Test-Path ($global:LogFileName)))
    {
        $currenttime = Get-Date -format u;
        $outputstring = "[" +  $currenttime + "] " + $message;
        $outputstring | Out-File $global:LogFileName -Append;
    }        
}


############################################################################################

### FUNCTION: CHECKS IF DEFENDER AND WD FILTER ARE ACTUALLY RUNNING OR NOT 

############################################################################################
function DisplayMachineInfo
{
    
    Write-ColorOutput Cyan "SYSTEM INFO:"    
    Write-ColorOutput White " "
    
    try
    {
        $MachineInfo = Get-ComputerInfo
        
    }
    catch [system.exception]
    {
        Write-ColorOutput Red "    Exception while querying computer Info. Skipping it..."  
        return
    }

    $tmp = $MachineInfo.CsDNSHostName
    Write-ColorOutput Yellow "   Computer Name:        $tmp  "
    
    $tmp = $MachineInfo.CsDomain
    Write-ColorOutput White "   Domain:               $tmp  "
    
    $tmp = $MachineInfo.WindowsBuildLabEx
    Write-ColorOutput White "   OS Build Name:        $tmp  "
    
    $tmp = $MachineInfo.WindowsProductName 
    Write-ColorOutput White "   Product Name:         $tmp  "
    
    #$tmp = $MachineInfo.OsHotFixes
    #Write-ColorOutput White "   Hot fix (KB):    $tmp  "    
    
    $tmp = $MachineInfo.CsSystemType
    Write-ColorOutput White "   Device Arch:          $tmp  "
    
    $tmp = $MachineInfo.CsModel
    Write-ColorOutput White "   Model:                $tmp  "
    
    $tmp = $MachineInfo.OsName
    Write-ColorOutput White "   OS Name:              $tmp  "

    $tmp = $MachineInfo.CsPrimaryOwnerName
    Write-ColorOutput White "   Primary User:         $tmp  "
    
    $tmp = $MachineInfo.CsPartOfDomain
    Write-ColorOutput White "   PartOfDomain?:        $tmp  "

}


############################################################################################

### FUNCTION: CHECKS IF DEFENDER AND WD FILTER ARE ACTUALLY RUNNING OR NOT 

############################################################################################

function CheckWDRunning
{

    Write-ColorOutput Cyan "CHECKING IF DEFENDER SERVICE RUNNING:"    
    Write-ColorOutput White " "
        
    try 
    { 
        $defenderOptions = Get-MpComputerStatus -ErrorAction SilentlyContinue
 
        if([string]::IsNullOrEmpty($defenderOptions)) 
        { 
            Write-ColorOutput Red "   Microsoft Defender Service not running. DLP won't work without Defender"   
            $global:bDLPMinReqOS = $false                       

        } 
        else 
        { 
            
            if($defenderOptions.AntivirusEnabled -eq $true)
            {
                Write-ColorOutput Green "    Microsoft Defender Service running. Looks Good"             
            }
            else
            {
                Write-ColorOutput Red "    Microsoft Defender Service not running. DLP won't work without Defender..."  
                $global:bDLPMinReqOS = $false            
            }
        } 
    } 
    catch [System.Exception]
    {

        Write-ColorOutput Red "Unable to query Microsoft Defender service status "        
    }
    
}

############################################################################################

### FUNCTION: CHECK THE OFFICE VERSION (Need this for Office Enlightenment feature)

############################################################################################

function GetOfficeVersion
{

    Write-ColorOutput Cyan "CHECKING OFFICE VERSION:" 
    Write-ColorOutput White " "   

    [string]$OfficeInstVer = ""    
    ## It is observed that diff machines has diff reg key to check for office version
    [string]$keyreg1 = "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration"
    [string]$keyreg2 = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\O365*"
    [string]$keyreg3 = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Office*"
   
    if(Test-Path $keyreg1)
    {
        try
        {
            $OfficeInstVer = (Get-ItemProperty -Path $keyreg1).VersionToReport       
        }
        catch [System.Exception]
        {
            Write-ColorOutput red "    ERROR: Exception while querying the Office installation version (1). Exiting..."
            Write-ColorOutput White " "
    
            return
        }
    }
   elseif(Test-Path $keyreg2)
   {
       try
        {
            $OfficeInstVer = (Get-ItemProperty -Path $keyreg2).DisplayVersion       
        }
        catch [System.Exception]
        {
            Write-ColorOutput red "    ERROR: Exception while querying the Office installation version (2). Exiting..."
            Write-ColorOutput White " "
    
            return
        }
   }
   elseif(Test-Path $keyreg3)
   {
       try
        {
            $OfficeInstVer = (Get-ItemProperty -Path $keyreg3).DisplayVersion       
        }
        catch [System.Exception]
        {
            Write-ColorOutput red "    ERROR: Exception while querying the Office installation version (3). Exiting..."
            Write-ColorOutput White " "
    
            return
        }
   }
   else
   {
      Write-ColorOutput Yellow "    INFO: Unable to Query the Office version. Please check if Office is installed"
      return
   }    

   Write-ColorOutput Yellow "    Current Office version is ==> $OfficeInstVer"
   Write-ColorOutput White " "

}


############################################################################################

### FUNCTION: CHECK IF THE OFFICE-ENLIGHTENMENT FEATURE IS ENABELD OR NOT

############################################################################################
function CheckOfficeEnlightenmentReg
{

    Write-ColorOutput Cyan "CHECKING OFFICE ENLIGHTENMENT CONFIGURATION:" 
    Write-ColorOutput White " "   
   [string]$keyreg = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features"
   
    if(Test-Path $keyreg)
    {
        try
        {
            $a = (Get-ItemProperty -Path $keyreg).DlpAppEnlightenmentSettings       
        }
        catch [System.Exception]
        {
            Write-ColorOutput red "    ERROR: Exception while querying the DlpAppEnlightenmentSettings Registry (1). Exiting..."
            Write-ColorOutput White " "
    
            return
        }
    }
   

   if($a -eq $null)
   {
       Write-ColorOutput White "    DlpAppEnlightenmentSettings registry missing. Goes with default"
   }
   elseif($a -eq 1)
   {
       Write-ColorOutput Green "    DlpAppEnlightenmentSettings is 1. Office Enlightenment Feature is enabled"
   }
   elseif($a -eq 0)
   {
      Write-ColorOutput Yellow "    DlpAppEnlightenmentSettings is 0. Office Enlightenment Feature is disabled"
   }   

    Write-ColorOutput White " "

}

############################################################################################

### FUNCTION: CHECK IF WEBSITE_DLP FEATURE IS ENABELD OR NOT

############################################################################################
function CheckDLPWebsiteReg
{

    Write-ColorOutput Cyan "CHECKING WEBSITE DLP CONFIGURATION:" 
    Write-ColorOutput White " "   
   [string]$keyreg = "HKLM:\SOFTWARE\Microsoft\Windows Defender\DLP Websites"

    if(Test-Path $keyreg)
    {
        try
        {
            $a = (Get-ItemProperty -Path $keyreg).Enabled       
        }
        catch [System.Exception]
        {
            Write-ColorOutput red "    ERROR: Exception while querying the DLP website registry. Exiting..."
            Write-ColorOutput White " "
    
            return
        }
    }
   

   if($a -eq $null)
   {
       Write-ColorOutput White "    DLP website registry missing. Goes with default"
   }
   elseif($a -eq 1)
   {
       Write-ColorOutput Green "    DLP website Enabled is 1. DLP website Feature is enabled"
   }
   elseif($a -eq 0)
   {
      Write-ColorOutput Yellow "    DLP website Enabled is 0. DLP website Feature is disabled"
   }   

    Write-ColorOutput White " "

}



############################################################################################

### FUNCTION: GET THE CURRENT INSTALLED MoCAMP VERSION 

############################################################################################

function GetCurrentMoCAMPVersion
{

    Write-ColorOutput Cyan "CHECKING MOCAMP VERSION:" 
    Write-ColorOutput White " "   
    [string]$MoCAMPInstPath = ""
    [string]$MoCAMPInstVer = ""
    [string]$keyreg = "HKLM:\SOFTWARE\Microsoft\Windows Defender"
    
    
    ## query the MoCAMP installation path
    try
    {
        $MoCAMPInstPath = (Get-ItemProperty -Path $keyreg).InstallLocation       
    }
    catch [System.Exception]
    {
        Write-ColorOutput red "    ERROR: Exception while querying the MoCAMP installation path. Exiting..."
        Write-ColorOutput White " "
    
        return
    }

    ## If NULL string, then something went wrong with the above query. Log and Exit...
    if( $MoCAMPInstPath -eq "" -or $MoCAMPInstPath -eq " ")
    {
        Write-ColorOutput Red "    WARN: Unable to query MoCAMP installation path: $MoCAMPInstPath. Exiting..."
        Write-ColorOutput White " "    
        return
    }


    #Write-ColorOutput Yellow "    INFO: MoCAMP Install path is-> $MoCAMPInstPath"
    ##Check if it has inbox version or installed MoCAMP version    
    if($MoCAMPInstPath.ToLower().contains('platform'))
    {
        $ArrStr = $MoCAMPInstPath.Split("\")
        
        if(-Not($ArrStr.Count -lt 2))
        {
            $MoCAMPInstVer = $ArrStr[$ArrStr.Count-2]
        }

        #Write-ColorOutput White "    MoCAMP version read: $MoCAMPInstVer"
        
        ### strip off the multi install number for the same version
        if($MoCAMPInstVer.Contains("-"))
        {
            $MoCAMPInstVer = $MoCAMPInstVer.Substring(0, $MoCAMPInstVer.IndexOf("-"))
        }
        
        Write-ColorOutput Yellow "    Current MoCAMP version ==> $MoCAMPInstVer"
        $global:CurMoCAMPVer = $MoCAMPInstVer        
    }
    else
    {
        Write-ColorOutput Green "    It has an inbox MoCAMP version"
    }
 
    IsMoCAMPUpdateNeeded
    
}




############################################################################################

### FUNCTION: NOTIFIES USER IF MOCAMP UPDATE IS NEEDED

############################################################################################

function IsMoCAMPUpdateNeeded
{
    
    Write-ColorOutput White "    Min MoCAMP version needed : $global:MIN_MOCAMPVER_NEEDED"

    $ArrCurVer = ($global:CurMoCAMPVer).Split(".")
    $ArrMinMoCAMPVer = ($global:MIN_MOCAMPVER_NEEDED).Split(".")

    if(-Not($ArrCurVer.Count -eq $ArrMinMoCAMPVer.count) -or ($ArrCurVer.Count -lt 4))
    {
        Write-ColorOutput Red "    ERROR: SubPart count for Cur-> $ArrCurrVer.count  MinMoCAMPVer->$ArrMinMoCAMPVer.count. Skipping update..."
        return
    }
    

      if( ( [int]$ArrCurVer[0] -lt [int]$ArrMinMoCAMPVer[0]) -or 
         ( ([int]$ArrCurVer[0] -eq [int]$ArrMinMoCAMPVer[0]) -and ([int]$ArrCurVer[1] -lt [int]$ArrMinMoCAMPVer[1])) -or 
         ( ([int]$ArrCurVer[0] -eq [int]$ArrMinMoCAMPVer[0]) -and ([int]$ArrCurVer[1] -eq [int]$ArrMinMoCAMPVer[1]) -and ([int]$ArrCurVer[2] -lt [int]$ArrMinMoCAMPVer[2])) -or
         ( ([int]$ArrCurVer[0] -eq [int]$ArrMinMoCAMPVer[0]) -and ([int]$ArrCurVer[1] -eq [int]$ArrMinMoCAMPVer[1]) -and ([int]$ArrCurVer[2] -eq [int]$ArrMinMoCAMPVer[2]) -and ([int]$ArrCurVer[3] -lt [int]$ArrMinMoCAMPVer[3]) ))
    {
        Write-ColorOutput Red "    INFO: Current MoCAMP version is old. Might need update for DLP feature to work"
    
    }
    else
    {
        Write-ColorOutput White " "
        Write-ColorOutput Green "    INFO: Min MoCAMP Version requirements met. Looks Good"
    }
}




############################################################################################

### FUNCTION: GET THE CURRENT ENGINE VERSION 

############################################################################################

function GetCurrentEngVersion
{

    Write-ColorOutput Cyan "CHECKING ENGINE VERSION:"    
    Write-ColorOutput White " "
    
    [string]$EngInstPath = ""
    [string]$EngRegKey = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Signature Updates"

    try
    {
        $EngInstPath = (Get-ItemProperty -Path $EngRegKey).SignatureLocation
    }
    catch [System.Exception]
    {
        Write-ColorOutput Red "    ERROR: Exception while querying the Engine installation path.Exiting...."
        return
    }

    [string]$EngInstDll = $EngInstPath + "\mpengine.dll"
    
    #Write-ColorOutput White "    Curr Eng Dll full Path-> $EngInstDll"
    
    if(-Not(Test-Path($EngInstDll)))
    {
        Write-ColorOutput Red "    WARN: Unable to findout the current engine dll. Can't find the Engine version "
        Write-ColorOutput Red "    WARN: Path-> $EngInstDll"        
        $global:bDLPMinReqOS = $false            
        return
    }
    
    try
    {
        $global:CurEngVer = (get-command $EngInstDll).FileVersionInfo.Productversion        
    }
    catch [System.Exception]
    { 
        Write-ColorOutput Red "    ERROR: Exception while querying the engine version. Exiting...."
        return
    }

    Write-ColorOutput Yellow "    Current Installed Engine Version is ===> $global:CurEngVer"
    IsEngineUpdateNeeded
    

}




############################################################################################

### FUNCTION: NOTIFIES USER IF ENGINE UPDATE IS NEEDED

############################################################################################

function IsEngineUpdateNeeded
{
    
    Write-ColorOutput White "    Min MoCAMP version needed : $global:MIN_ENGINEVER_NEEDED"

    $ArrCurrEngVer = ($global:CurEngVer).Split(".")
    $ArrMinEngVer = ($global:MIN_ENGINEVER_NEEDED).Split(".")

    if(-Not($ArrCurrEngVer.Count -eq $ArrMinEngVer.count) -or ($ArrCurrEngVer.Count -ne 4))
    {
        Write-ColorOutput Red "    ERROR:Engine ver check. SubPart count for Cur-> $ArrCurrEngVer.count Min-> $ArrMinEngVer.count. Skipping update"
        return
    }

    
    if( ([int]$ArrCurrEngVer[0] -lt [int]$ArrMinEngVer[0]) -or  
        ([int]$ArrCurrEngVer[1] -lt [int]$ArrMinEngVer[1]) -or 
        ([int]$ArrCurrEngVer[2] -lt [int]$ArrMinEngVer[2]) -or 
        ([int]$ArrCurrEngVer[3] -lt [int]$ArrMinEngVer[3]) )
    {
        
        Write-ColorOutput Red "    INFO: Current Engine version is old. Might need update for DLP feature to work"
        $global:bDLPMinReqOS = $false 
    
    }
    else
    {
        Write-ColorOutput White " "
        Write-ColorOutput Green "    INFO: Min Engine Version requirements met. Looks Good"
        
    }
}





############################################################################################

### FUNCTION: CHECKS THE OS VERISON 

############################################################################################

function GetOSBuildNum
{
    
    Write-ColorOutput Cyan "CHECKING OS BUILD VERSION:"
    Write-ColorOutput White " "
    
    try
    {
        $global:OSBuildNum = Invoke-Expression "([System.Environment]::OSVersion.Version).Build"
    }
    catch [system.exception]
    {
        Write-ColorOutput Red "  Exception while querying the OS build version number $Error"
    }
        

    if($OSBuildNum -lt 17763)
    {
        Write-ColorOutput Red "   Build version Num:$global:OSBuildNum  Min OS needed is RS5. Current OS does not support DLP"     
        $global:bDLPMinReqOS = $false       
    }
    elseif($OSBuildNum -eq 17763)
    {
        Write-ColorOutput Green "   Build version Num:$global:OSBuildNum  OS: RS5 Release"            
    }
    elseif($OSBuildNum -eq 18362)
    {
        Write-ColorOutput Green "   Build version Num:$global:OSBuildNum  OS: 19H1 Release"            
            
    }
    elseif($OSBuildNum -eq 18363)
    {
        Write-ColorOutput Green "   Build version Num:$global:OSBuildNum  OS: 19H2 Release"                        
    }
    elseif($OSBuildNum -eq 19041)
    {
        Write-ColorOutput Green "   Build version Num:$global:OSBuildNum  OS: VB Release"                        
    }
    else
    {
        Write-ColorOutput Green "   Build version Num:$global:OSBuildNum  OS: Mn or Fe Release"
    } 
    
}




############################################################################################

### FUNCTION: CHECKS THE SENSE ONBOARD REG ARE ALREADY PRESENT OR NOT

############################################################################################

function CheckSenseOnBoardReg
{
    Write-ColorOutput Cyan "CHECKING SENSE ONBOARDING REGS:"
    Write-ColorOutput White " "
    
    Write-ColorOutput White "   Reg1 check-->"
    ### MDE Reg1 check
    try
    {  
        $a = Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" | Select-Object -ExpandProperty "GroupIds" -ErrorAction SilentlyContinue 

        if($a -eq $null)
        {
            Write-ColorOutput Yellow "   Missing MDE Reg entry. Key='GroupIds' Value='EnableDlpEnforcement' under 'HKLM:SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection'"
            Write-ColorOutput Red "   Please add above mentioned Registry entry without which DLP feature may not work for older OS [RS5 or 19H1]"
            
        }
        else
        {
            if($a -eq "EnableDlpEnforcement")
            {
                Write-ColorOutput Green "   Reg1->GroupIds (MDE)Regkey set properly for EnableDlpEnforcement. Looks Good"
            }
            else
            {
                Write-ColorOutput Yellow "   GroupIds (MDE)Regkey exists but not properly set as EnableDlpEnforcement"
            }
        }
    }
    catch [System.exception]
    {
        Write-ColorOutput Red "   Exception while querying or adding reg keys to onboard SENSE OS"
    }


    Write-ColorOutput White " "
    Write-ColorOutput White "   Reg2 check-->"
    ### ATP Reg2 check
    try
    {
        if(-Not(Test-Path("HKLM:SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\DeviceTagging")))
        {
            
            Write-ColorOutput Yellow "   Missing MDE Reg Entry: Key='DLP' Value='EnableDlpEnforcement' under 'HKLM:SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\DeviceTagging'"
            Write-ColorOutput Red "   Please add above mentioned Registry entry without which DLP feature may not work for older OS [RS5 or 19H1]"
            return
        }
        
        
        $b = Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\DeviceTagging" | Select-Object -ExpandProperty "DLP" -ErrorAction SilentlyContinue 
        if($b -eq $null)
        {
            Write-ColorOutput Yellow "   Missing MDE Reg Entry: Key='DLP' Value='EnableDlpEnforcement' under 'HKLM:SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\DeviceTagging'"
            Write-ColorOutput Red "   Please add above mentioned Registry entry without which DLP feature may not work"
            
        }
        else
        {
            if($b -eq "EnableDlpEnforcement")
            {
                Write-ColorOutput Green "   Reg2->DLP (MDE)Regkey set properly for EnableDlpEnforcement. Looks Good"
            }
            else
            {
                Write-ColorOutput Green "   DLP (MDE)Regkey exists but not properly as EnableDlpEnforcement"
            }
        }
    }
    catch [System.exception]
    {
        Write-ColorOutput Red "   Exception while querying or adding reg keys to onboard SENSE OS"
    }

}





############################################################################################

### FUNCTION: CHECKS IF DLP FEATURE IS ENABLED ON THIS MACHINE

############################################################################################

function CheckDLPEnabled
{

    Write-ColorOutput Cyan "CHECK REG IF DLP FEATURE IS ENABLED:"
    Write-ColorOutput White " "
        
    try
    {
        if(-Not(Test-Path("HKLM:SOFTWARE\Microsoft\Windows Defender\Features")))
        {
            
            Write-ColorOutput Red "   ERROR: Did not find the reg path 'SOFTWARE\Microsoft\Windows Defender\Features'"
            return
        }
        
        #SenseEnabled reg check
        $b = Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows Defender\Features" | Select-Object -ExpandProperty "SenseEnabled" -ErrorAction SilentlyContinue 
        if($b -ne $null)
        {

            if($b -eq 1)
            {
                Write-ColorOutput Green "   SenseEnabled is set to TRUE. Looks Good"
            }
            else
            {
                Write-ColorOutput Red "   SenseEnabled is not enabled. Please contact your administrator"
                $global:bDLPMinReqOS = $false
            }

        }
        else
        {
           Write-ColorOutput Red "  The reg key SenseEnabled does not exists"
           $global:bDLPMinReqOS = $false         
        }

        
        #SenseDlpEnabled reg check
        $b = Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows Defender\Features" | Select-Object -ExpandProperty "SenseDlpEnabled" -ErrorAction SilentlyContinue 
        if($b -ne $null)
        {

            if($b -eq 1)
            {
                Write-ColorOutput Green "   SenseDlpEnabled is enabled. Looks Good"
            }
            else
            {
                Write-ColorOutput Red "   SenseDlpEnabled is not enabled for the DLP feature. Please contact your administrator"
                $global:bDLPMinReqOS = $false
            }

        }
        else
        {
           Write-ColorOutput Red "  The reg key SenseDlpEnabled does not exists"
           $global:bDLPMinReqOS = $false         
        }


        #Dlp Show bypass reason UX reg check
        $b = Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows Defender\Features" | Select-Object -ExpandProperty "SenseDlpShowBypassReasonUx" -ErrorAction SilentlyContinue 
        if($b -ne $null)
        {

            Write-ColorOutput Yellow "   SenseDlpShowBypassReasonUx is: $b"            

        }
        else
        {
           Write-ColorOutput Yellow "  The reg key SenseDlpShowBypassReasonUx does not exists"           
        }
        

        #Sense org id check
        $b = Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows Defender\Features" | Select-Object -ExpandProperty "SenseOrgId" -ErrorAction SilentlyContinue 
        if($b -ne $null)
        {
            
            Write-ColorOutput Yellow "   SenseOrgId is: $b"            

        }
        else
        {
           Write-ColorOutput Red "  The reg key SenseOrgId does not exists"
           $global:bDLPMinReqOS = $false
        }

        #MpCapability reg check
        $b = Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows Defender\Features" | Select-Object -ExpandProperty "MpCapability" -ErrorAction SilentlyContinue
         if($b -ne $null)
        {
            
            Write-ColorOutput Yellow "   MpCapability is: $b"            

        }
        else
        {
           Write-ColorOutput Yellow "  The reg key MpCapability does not exists"
           Write-ColorOutput Yellow "  The DLP experience may not be as expected"                 
        }

    }
    catch [System.exception]
    {
        Write-ColorOutput Red "   Exception while querying or adding reg keys to onboard SENSE OS"
    }

}



############################################################################################

### FUNCTION: CHECKS IF UX CONFIGURATION SETTINGS ARE ENABLED OR DISABLED

############################################################################################

function CheckUXConfiguraitonSettings
{

    Write-ColorOutput Cyan "CHECKING UX CONFIGURATION REG SETTINGS:"
    Write-ColorOutput White " "
    

    ### Post June 2020 MoCAMP, these GP controlled registries will not impact DLP toast display
    ## However, have them checked and display info to the user 
    ## Below is for UILockdown registry
    try
    {
        if(Test-Path("HKLM:SOFTWARE\Policies\Microsoft\Microsoft Antimalware\UX Configuration"))
        {
            Write-ColorOutput White "   Checking the reg: UILockdown..."            
            $b = Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Microsoft\Microsoft Antimalware\UX Configuration" | Select-Object -ExpandProperty "UILockdown" -ErrorAction SilentlyContinue 
            if($b -eq $null)
            {
                Write-ColorOutput Yellow "   INFO: Did not find 'UILockdown' under 'HKLM:SOFTWARE\Policies\Microsoft\Microsoft Antimalware\UX Configuration'. Goes with default"                
            
            }
            else
            {
               if($b -eq 0)
               {

                    Write-ColorOutput Green "   Group Policy Notification settings for UI lockdown is disabled. Looks Good"                                
                
               }
               else
               {
                    Write-ColorOutput Yellow "   WARNING: Group policy settings for UILockdown is enabled. "                 
                    Write-ColorOutput Yellow "   Please contact your administrator in case no DLP toast is seen"
                
               }
            }


            ### Post June 2020 MoCAMP, these GP controlled registries will not impact DLP toast display
            ## However, have them checked and display info to the user 
            ## Below is for Notification_Suppress registry
            Write-ColorOutput White "   Checking the reg: Notification_Suppress..."            
            $b = Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Microsoft\Microsoft Antimalware\UX Configuration" | Select-Object -ExpandProperty "Notification_Suppress" -ErrorAction SilentlyContinue 
            if($b -eq $null)
            {
                Write-ColorOutput Yellow "   INFO: Did not find 'Notification_Suppress' under 'HKLM:SOFTWARE\Policies\Microsoft\Microsoft Antimalware\UX Configuration'. Goes with default"                
            }
            else
            {
               if($b -eq 0)
               {

                    Write-ColorOutput Green "   Group Policy Notification settings for Notification supress is disabled. Looks Good"                
               }
               else
               {
                    Write-ColorOutput Yellow "   WARNING: Group policy settings for Notification Supress is enabled "                 
                    Write-ColorOutput Yellow "   Please contact your administrator in case no DLP toast is observed"
                
               }
            }

        }
        else
        {            
            Write-ColorOutput Yellow "   INFO: Did not find the reg path 'HKLM:SOFTWARE\Policies\Microsoft\Microsoft Antimalware\UX Configuration'. Goes with default"            
        }
       
    }
    catch [System.exception]
    {
        Write-ColorOutput Red "   Exception while querying the GPM UILockdown/Notification_Suppress reg settings "
        return
    }


    Write-ColorOutput White " "
    Write-ColorOutput White " "
        
    ### Do the same reg check but this time under WDAV reg path
    try
    {
        if(Test-Path("HKLM:SOFTWARE\Microsoft\Windows Defender\UX Configuration"))
        {

            $b = Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows Defender\UX Configuration" | Select-Object -ExpandProperty "UILockdown" -ErrorAction SilentlyContinue 
            if($b -eq $null)
            {
                Write-ColorOutput Yellow "   INFO: Did not find 'UILockdown' under 'HKLM:SOFTWARE\Microsoft\Windows Defender\UX Configuration'. Goes with default"                
            
            }
            else
            {
               if($b -eq 0)
               {
                    Write-ColorOutput Green "   WDAV settings for UI lockdown is disabled. Looks Good"                                                
               }
               else
               {
                    Write-ColorOutput Yellow "   WARNING: WDAV settings for UILockdown is enabled. "                 
                    Write-ColorOutput Yellow "   Please contact your administrator in case no DLP toast is observed"                
               }
            }
        }
        else
        {            
            Write-ColorOutput Yellow "   INFO: Did not find the reg path 'HKLM:SOFTWARE\Microsoft\Windows Defender\UX Configuration'. Goes with default"                    
        }


        $b = Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows Defender\UX Configuration" | Select-Object -ExpandProperty "Notification_Suppress" -ErrorAction SilentlyContinue 
        if($b -eq $null)
        {
            Write-ColorOutput Yellow "   Did not find 'Notification_Suppress' under 'HKLM:SOFTWARE\Microsoft\Windows Defender\UX Configuration'. Goes with default"            
            
        }
        else
        {
           if($b -eq 0)
           {

                Write-ColorOutput Green "   WDAV Notification settings for Notification supress is disabled. Looks Good"                                
                
           }
           else
           {
                Write-ColorOutput Yellow "   WARNING: WDAV settings for Notification Supress is enabled "                 
                Write-ColorOutput Yellow "   Please contact your administrator in case no DLP toast is observed"
                
           }
        }

    }
    catch [System.exception]
    {
        Write-ColorOutput Red "   Exception while querying the WDAV UILockdown reg settings "
    }

    Write-ColorOutput White " "
    Write-ColorOutput White " "

}




############################################################################################

### FUNCTION: CHECKS IF TOAST SETTINGS ARE ENABLED OR DISABLED

############################################################################################

function CheckNotificationSettings
{

    Write-ColorOutput Cyan "CHECKING NOTIFICATION SETTINGS:"
    Write-ColorOutput White " "
        

    #### ToastEnabled reg check    
    try
    {
        if(Test-Path("HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications"))
        {
            Write-ColorOutput White "   Checking ToastEnabled reg key settings..."
            $b = Get-ItemProperty -Path "HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" | Select-Object -ExpandProperty "ToastEnabled" -ErrorAction SilentlyContinue 
            if($b -eq $null)
            {
                Write-ColorOutput Yellow "   INFO: Missing 'ToastEnabled' under 'HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications'. Goes with default"
                Write-ColorOutput Yellow "   INFO: If still no toast, please try enabling 'Settings->System->Notification & Action->Get notifications from apps'"                           
            
            }
            else
            {
               if($b -eq 1)
               {
                    Write-ColorOutput Green "   Notification settings (ToastEnabled) is enabled. Looks Good"                
               }
               else
               {
                    Write-ColorOutput Yellow "   WARNING: Notification settings for toast not enabled. You may not see DLP toasts for  block/warn operations"                 
                    Write-ColorOutput Yellow "   Goto Settings -> System -> Notification & Action -> Enable the Notification button for better DLP experience"
               }
            }
            
        }
        else
        {
            Write-ColorOutput Yellow "   INFO: Did not find the reg path 'HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications' for 'ToastEnabled'"            
        }
        
    }
    catch [System.exception]
    {
        Write-ColorOutput Red "   Exception while querying the toast settings "
    }

    
    Write-ColorOutput White " "
        
    try
    {
        
        if(Test-Path("HKCU:SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"))
        {

            Write-ColorOutput White "   Checking NoToastApplicationNotification reg key settings..."

            $b = Get-ItemProperty -Path "HKCU:SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" | Select-Object -ExpandProperty "NoToastApplicationNotification" -ErrorAction SilentlyContinue 
            if($b -eq $null)
            {
                Write-ColorOutput Yellow "   Missing NoToastApplicationNotification registry under the path 'HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'"
                Write-ColorOutput Green "   INFO: Policy not set to disable DLP toasts, looks good. If still issue with toasts, please contact your administrator"           
                            
            }
            else
            {

                if($b -eq 1)
               {
                    Write-ColorOutput Yellow "   WARN: Notification settings NoToastApplicationNotification is enabled"    
                    Write-ColorOutput Yellow "   Policies set to disable toast notification. You may not see DLP toasts for block/warn operations. Please contact your administrator"                                             
               }
               else
               {
                    Write-ColorOutput Yellow "   Policies set to enabled toast the notification. Looks Good."                                             
               }
            }
        }
        else
        {
            Write-ColorOutput Yellow "   INFO: Did not find the reg path 'HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications' for 'NoToastApplicationNotification'"           
            
        }
    }
    catch [System.exception]
    {
        Write-ColorOutput Red "   Exception while querying the toast settings "
    }

}




############################################################################################

### FUNCTION: CHECKS IF DLP SHOW DIALOG REG IS ENABLED OR NOT 

############################################################################################

function CheckDLPShowDialog
{

    Write-ColorOutput Cyan "CHECKING DLP DIALOG BOX SETTINGS:"
    Write-ColorOutput White " "
    
    try
    {
        if(-Not(Test-Path("HKLM:software\microsoft\windows defender\Miscellaneous Configuration")))
        {
            
            Write-ColorOutput Red "   ERROR: Reg path not found. HKLM:software\microsoft\windows defender\Miscellaneous Configuration'"
            return
        }
        
        
        $b = Get-ItemProperty -Path "HKLM:software\microsoft\windows defender\Miscellaneous Configuration" | Select-Object -ExpandProperty "DlpShowDialogs" -ErrorAction SilentlyContinue 
        if( ($b -eq $null) -or ($b -eq 1) )
        {

            if($b -eq $null)
            {
                Write-ColorOutput Yellow "   INFO: DlpShowDialogs is missing. Default behavior is to show error dialog boxes for DLP operations "            
            }
            else
            {
                Write-ColorOutput Yellow "   INFO: DlpShowDialogs is set to 1. Shows the error dialog boxes for DLP operations "            
            }
            return
        }
        else
        {
            Write-ColorOutput Yellow "   INFO: DlpShowDialogs reg is set to 0. Error dialog box will be suppressed for DLP operations "                                 
           
        }
    }
    catch [System.exception]
    {
        Write-ColorOutput Red "   Exception while querying the toast settings "
    }

}




############################################################################################

### FUNCTION: CHECKS IF INBOX OS BACKPORT CHANGES ARE AVAILABLE OR MISSING ON THIS PC

############################################################################################

function DLPInboxChangesBackportedToOS
{
    Write-ColorOutput Cyan "DLP INBOX BACKPORT CHANGE VERIFICATION:"
    Write-ColorOutput White " "
    
    [string]$BackPortFile = join-path $env:windir "System32"
    $BackPortFile = join-path $BackPortFile $global:DLPBackPortFile 


    #Write-ColorOutput White " Filepath is: $BackPortFile "
    if(Test-Path($BackPortFile))
    {        
        Write-ColorOutput Green "   DLP Inbox backport changes. Looks good"
        Write-ColorOutput White " "   
        
    }
    else
    {
        Write-ColorOutput Red "   DLP Inbox backport changes seems missing on this PC. DLP user experience may not be as expected on this device"
        Write-ColorOutput Yellow "   Windows Upgrade might be helpful"
    }
    
 }




############################################################################################

### FUNCTION: CHECKS THE CONFIGURATION FOR BEHAVIOUR MONITORING UNDER POLICY MANAGER

############################################################################################

function CheckBMConfig_PolManager
{

    Write-ColorOutput Cyan "BEHAVIOR MONITORING CONFIGURATION CHECK [POLICY MANAGER]:"
    Write-ColorOutput White " "
    
    try
    {

        Write-ColorOutput White "   Checking Behavior and Realtime Monitoring registry settings under policy manager "

        if(-Not(Test-Path("HKLM:SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager")))
        {
            
            Write-ColorOutput Red "   INFO: Did not find the reg path 'SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager'"
            return
        }
        
        
        $a = Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" | Select-Object -ExpandProperty "AllowBehaviorMonitoring" -ErrorAction SilentlyContinue 
        if($a -eq $null)
        {
            Write-ColorOutput Yellow "   INFO: Missing Allow Behavior Monitoring regkey under the path 'HKLM:SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager'"
            
        }
        else
        {
           if($a -eq 1)
           {

                Write-ColorOutput Green "   Behavior Monitoring settings under policy manager is enabled. Looks Good"                                
                
           }
           else
           {
                Write-ColorOutput Red "   WARN: Behavior Monitoring settings under policy manager is disabled"                                 
                
           }
        }
        Write-ColorOutput White " "
        

        $b = Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" | Select-Object -ExpandProperty "AllowRealtimeMonitoring" -ErrorAction SilentlyContinue 
        if($b -eq $null)
        {
            Write-ColorOutput Yellow "   INFO: Missing Allow RealTime Monitoring regkey under the path 'HKLM:SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager'"            
        }
        else
        {
           if($a -eq 1)
           {

                Write-ColorOutput Green "   Realtime Monitoring settings under policy manager is enabled. Looks Good"                                
                
           }
           else
           {
                Write-ColorOutput Red "   WARN: Realtime Monitoring settings under policy manager is disabled"                                 
                
           }
        }
        Write-ColorOutput White " "
        Write-ColorOutput White " "

        
        
    }
    catch [System.exception]
    {
        Write-ColorOutput Red "   Exception while querying or adding reg keys to onboard SENSE OS"
    }    
}



############################################################################################

### FUNCTION: CHECKS THE POLICY CONFIGURATION FOR BEHAVIOUR MONITORING

############################################################################################

function CheckBMConfig
{

    Write-ColorOutput Cyan "BEHAVIOR MONITORING CONFIGURATION CHECK:"
    Write-ColorOutput White " "
    
    try
    {

        Write-ColorOutput White "   Checking Behavior and Realtime Monitoring registry settings under RTP policies..."

        if(-Not(Test-Path("HKLM:SOFTWARE\Policies\Microsoft\Windows Defender\real-time protection")))
        {
            
            Write-ColorOutput Yellow "   INFO: Did not find the reg path 'SOFTWARE\Policies\Microsoft\Windows Defender\real-time protection'"
            return            
        }
        
        
        $a = Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Microsoft\Windows Defender\real-time protection" | Select-Object -ExpandProperty "DisableBehaviorMonitoring" -ErrorAction SilentlyContinue 
        if($a -eq $null)
        {
            Write-ColorOutput Yellow "   Missing Behavior Monitoring regkey under the path 'HKLM:SOFTWARE\Policies\Microsoft\Windows Defender\real-time protection'"
            Write-ColorOutput Yellow "   DLP user experience may not be as expected "            
        }

        $b = Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Microsoft\Windows Defender\real-time protection" | Select-Object -ExpandProperty "DisableRealTimeMonitoring" -ErrorAction SilentlyContinue 
        if($b -eq $null)
        {
            Write-ColorOutput Yellow "   Missing RealTime Monitoring regkey under the path 'HKLM:SOFTWARE\Policies\Microsoft\Windows Defender\real-time protection'"
            Write-ColorOutput Red "   DLP toasts may not work on this PC"
            $global:bDLPMinReqOS = $false            
            return
        }
        
        Write-ColorOutput Green "   Reg settings for Behaviour and Realtime Monitoring are enabled. Looks Good "           
        
    }
    catch [System.exception]
    {
        Write-ColorOutput Red "   Exception while querying or adding reg keys to onboard SENSE OS"
    }
}




# function to read Registry Value
function Get-RegistryValue { param (
    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]$Path,
    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]$Value
    )

    if (Test-Path -path $Path) {
        return Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Value -ErrorAction silentlycontinue
    } else {
        return $false
    }
}





############################################################################################

### FUNCTION: CHECKS IF DLP POLICIES CONFIGURED FOR A SPECIFIC DLP ACTION TYPE

############################################################################################

function policychecker($CheckPolicyLogFile, $StrB, $StrW, $StrA, $Category)
{

    if ( (Get-Content -Path $CheckPolicyLogFile).Contains($StrB) -and
         (Get-Content -Path $CheckPolicyLogFile).Contains($StrW) -and
         (Get-Content -Path $CheckPolicyLogFile).Contains($StrA) )
            
    {
        Write-ColorOutput Yellow "   DLP Feature: $Category"
        Write-ColorOutput Green "    -- All Block/Warn/Audit policies found"
    }
    elseif(
            (Get-Content -Path $CheckPolicyLogFile).Contains($StrB) -or
            (Get-Content -Path $CheckPolicyLogFile).Contains($StrW) -or
            (Get-Content -Path $CheckPolicyLogFile).Contains($StrA) )
             
    {
    
        Write-ColorOutput Yellow "   DLP Feature: $Category"
        if(-Not((Get-Content -Path $CheckPolicyLogFile).Contains($StrB)))
       {
            
            Write-ColorOutput Yellow "   -- Block policy not found"
       }
       else
       {
            Write-ColorOutput Green "   -- Block policy found"
       }

       if(-Not((Get-Content -Path $CheckPolicyLogFile).Contains($StrW)))
       {
            Write-ColorOutput Yellow "   -- Warn policy not found"
            
       }
       else
       {
            Write-ColorOutput Green "   -- Warn policy found"
       }


       if(-Not((Get-Content -Path $CheckPolicyLogFile).Contains($StrA)))
       {
            Write-ColorOutput Yellow "   -- Audit policy not found"
       }
       else
       {
            Write-ColorOutput Green "   -- Audit policy found"
       }           

    }
    else
    {   
        Write-ColorOutput Yellow "    DLP Feature: $Category "
        Write-ColorOutput Red "    -- No policies found for this feature"
    }
}





############################################################################################

### FUNCTION: FUNCTION TO CHECK MACHINE LEVEL DLP POLICES

############################################################################################

function CheckDeviceDLPPolicies($CheckPolicyLogFile)
{
        
        if(Test-Path $CheckPolicyLogFile)
        {
            $USBBlock = 'CopyToRemovableMedia":{"EnforcementMode":3}'
            $USBWarn = 'CopyToRemovableMedia":{"EnforcementMode":2}'
            $USBAudit = 'CopyToRemovableMedia":{"EnforcementMode":1}'
            policychecker $CheckPolicyLogFile $USBBlock $USBWarn $USBAudit "CopyToRemovableMedia"
            Write-ColorOutput White " "
            

            $NetworkBlock = 'CopyToNetworkShare":{"EnforcementMode":3}'
            $NetworkWarn = 'CopyToNetworkShare":{"EnforcementMode":2}'
            $NetworkAudit = 'CopyToNetworkShare":{"EnforcementMode":1}'
            policychecker $CheckPolicyLogFile $NetworkBlock $NetworkWarn $NetworkAudit "CopyToNetworkShare"
            Write-ColorOutput White " " 

            
            $ClipboardBlock = 'CopyToClipboard":{"EnforcementMode":3}'
            $ClipboardWarn = 'CopyToClipboard":{"EnforcementMode":2}'
            $ClipboardAudit = 'CopyToClipboard":{"EnforcementMode":1}'
            policychecker $CheckPolicyLogFile $ClipboardBlock $ClipboardWarn $ClipboardAudit "CopyToClipboard"
            Write-ColorOutput White " "


            $PrintBlock = 'Print":{"EnforcementMode":3}'
            $PrintWarn = 'Print":{"EnforcementMode":2}'
            $PrintAudit = 'Print":{"EnforcementMode":1}'
            policychecker $CheckPolicyLogFile $PrintBlock $PrintWarn $PrintAudit "Print"
            Write-ColorOutput White " "


            $UnallAppBlock = 'AccessByUnallowedApps":{"EnforcementMode":3}'
            $UnallAppWarn = 'AccessByUnallowedApps":{"EnforcementMode":2}'
            $UnallAppAudit = 'AccessByUnallowedApps":{"EnforcementMode":1}'
            policychecker $CheckPolicyLogFile $UnallAppBlock $UnallAppWarn $UnallAppAudit "AccessByUnallowedApps"
            Write-ColorOutput White " "
            
            $BluetoothAppBlock = 'UnallowedBluetoothTransferApps":{"EnforcementMode":3}'
            $BluetoothAppWarn = 'UnallowedBluetoothTransferApps":{"EnforcementMode":2}'
            $BluetoothAppAudit = 'UnallowedBluetoothTransferApps":{"EnforcementMode":1}'
            policychecker $CheckPolicyLogFile $BluetoothAppBlock $BluetoothAppWarn $BluetoothAppAudit "AccessByBluetoothApp"
            Write-ColorOutput White " "

            $RDPAppBlock = 'RemoteDesktopAccess":{"EnforcementMode":3}'
            $RDPAppWarn = 'RemoteDesktopAccess":{"EnforcementMode":2}'
            $RDPAppAudit = 'RemoteDesktopAccess":{"EnforcementMode":1}'
            policychecker $CheckPolicyLogFile $RDPAppBlock $RDPAppWarn $RDPAppAudit "RemoteDesktopAccess"
            Write-ColorOutput White " "            
           
        }
        else
        {
            Write-ColorOutput "    WARN: DLP device policy log not generated "
            return
        }
}




###############################################################################################################

### FUNCTION: FUNCTION TO POPULATE MACHINE LEVEL DLP RULES AND POLICES (PARSE REG SETTING AS PLAIN STRING)

#############################################################################################################

function PopulateDLPPolicies($CheckPolicyLogFile)
{

    Write-ColorOutput Cyan "POPULATE DLP POLICES:"
    if(-Not(Test-Path($CheckPolicyLogFile)))
    {
        Write-ColorOutput Red "dlp policy file not found. Can't popluate policies. Skipping..."
        return        
    }


    $line = Get-Content $CheckPolicyLogFile    
    
    
    ## PARSE ENLIGHTENED APPS LIST  
    $indx = $line.IndexOf("EnlightenedApplications")    
    if($indx -ge 0)
    {
        Write-ColorOutput white " "
        Write-ColorOutput yellow "ENLIGHTENED APPLICATIONS:"
        Write-ColorOutput white "------------------------"
        $line = $line.Substring($indx)        
        $startIndx = $line.IndexOf('[')
        $endIndx = $line.IndexOf(']')

        $enlightenStr = $line.Substring($startIndx+1, $endIndx - $startIndx + 1)
        $line = $line.Substring($endIndx)        
        #Write-ColorOutput yellow "enlighten string is $enlightenStr "
        
        $arr = $enlightenStr.Split('}')       
        for($i = 0; $i -lt $arr.count -1; $i++) 
        {
            if($i -eq 0) 
            {
                $temp = $arr[$i].Substring(1)
            }
            else
            {
                $temp = $arr[$i].Substring(2)
            }
            Write-ColorOutput white " $temp"
        }
    }


      
    ## PARSE UNALLOWED APPS LIST    
    Write-ColorOutput white " "  
    $indx = $line.IndexOf("UnallowedApplications")    
    if($indx -ge 0)
    {
        Write-ColorOutput white " "
        Write-ColorOutput yellow "UNALLOWED APPLICATIONS:"
        Write-ColorOutput white "--------------------"
    
        $line = $line.Substring($indx)        
        $startIndx = $line.IndexOf('[')
        $endIndx = $line.IndexOf(']')

       
        $unallowedStr = $line.Substring($startIndx+1, $endIndx - $startIndx + 1)
        $line = $line.Substring($endIndx)          
        
        #Write-ColorOutput yellow "Unallowed apps string is $unallowedStr "
                       
        $arr = $unallowedStr.Split('}')
        for($i = 0; $i -lt $arr.count - 1; $i++) 
        {
            if($i -eq 0) 
            {
                $temp = $arr[$i].Substring(1)
            }
            else
            {
                $temp = $arr[$i].Substring(2)
            }
            Write-ColorOutput white " $temp"
        }    
    }      

         
    ## PARSE UNALLOWED BROWSERS LIST
    Write-ColorOutput white " "
    $indx = $line.IndexOf("UnallowedBrowsers")    
    if($indx -ge 0)
    {
        Write-ColorOutput white " "
        Write-ColorOutput yellow "UNALLOWED BROWSERS:"
        Write-ColorOutput white "------------------"
        $line = $line.Substring($indx)        
        $startIndx = $line.IndexOf('[')
        $endIndx = $line.IndexOf(']')

        $unallowedBrowserStr = $line.Substring($startIndx+1, $endIndx - $startIndx + 1)
        $line = $line.Substring($endIndx)        

        #Write-ColorOutput yellow "Unallowed browser string is $unallowedBrowserStr "
        
        $arr = $unallowedBrowserStr.Split('}')
        for($i = 0; $i -lt $arr.count - 1; $i++) 
        {
            if($i -eq 0) 
            {
                $temp = $arr[$i].Substring(1)
            }
            else
            {
                $temp = $arr[$i].Substring(2)
            }
            Write-ColorOutput white " $temp"
        }            
    }


    ## PARSE CLOUD APP DOMAINS LIST
    Write-ColorOutput white " "
    $indx = $line.IndexOf("Domains")    
    if($indx -ge 0)
    {
        Write-ColorOutput white " "
        Write-ColorOutput yellow "CLOUD APP DOMAINS INFO:"
        Write-ColorOutput white "------------------"
        
        $line = $line.Substring($indx)        
        $startIndx = $line.IndexOf('[')
        $endIndx = $line.IndexOf(']')

        $CloudAppsDomainsStr = $line.Substring($startIndx+1, $endIndx - $startIndx + 1)
        $line = $line.Substring($endIndx)        

        #Write-ColorOutput yellow "Unallowed cloud app domains string is $unallowedDomainsStr "
        
        $arr = $CloudAppsDomainsStr.Split('}')
         
        for($i = 0; $i -lt $arr.count - 2; $i++) 
        {
            if($i -eq 0) 
            {
                $temp = $arr[$i].Substring(1)
            }
            else
            {
                $temp = $arr[$i].Substring(2)
            }
            Write-ColorOutput white " $temp"
        }            
    }



    ## PARSE BLUETOOTH APPS LIST 
    Write-ColorOutput white " "
    $indx = $line.IndexOf("UnallowedBluetoothApps")    
    if($indx -ge 0)
    {
        Write-ColorOutput white " "
        Write-ColorOutput yellow "UNALLOWED BLUETOOTH APPS:"
        Write-ColorOutput white "--------------------"
    
        $line = $line.Substring($indx)        
        $startIndx = $line.IndexOf('[')
        $endIndx = $line.IndexOf(']')

       
        $unallowedBtStr = $line.Substring($startIndx+1, $endIndx - $startIndx + 1)
        $line = $line.Substring($endIndx)          
        
        #Write-ColorOutput yellow "Unallowed apps string is $unallowedStr "
                       
        $arr = $unallowedBtStr.Split('}')
        for($i = 0; $i -lt $arr.count - 1; $i++) 
        {
            if($i -eq 0) 
            {
                $temp = $arr[$i].Substring(1)
            }
            else
            {
                $temp = $arr[$i].Substring(2)
            }
            Write-ColorOutput white " $temp"
        }    
    }
    
    ## PARSE UNALLOWED CLOUD SYNC APPS LIST
    Write-ColorOutput white " "
    $indx = $line.IndexOf("UnallowedCloudSyncApps")    
    if($indx -ge 0)
    {
        Write-ColorOutput white " "
        Write-ColorOutput yellow "UNALLOWED CLOUDSYNC APPS:"
        Write-ColorOutput white "--------------------"
    
        $line = $line.Substring($indx)        
        $startIndx = $line.IndexOf('[')
        $endIndx = $line.IndexOf(']')

       
        $unallowedCloudSyncStr = $line.Substring($startIndx+1, $endIndx - $startIndx + 1)
        $line = $line.Substring($endIndx)          
        
        #Write-ColorOutput yellow "Unallowed apps string is $unallowedStr "
                       
        $arr = $unallowedCloudSyncStr.Split('}')
        for($i = 0; $i -lt $arr.count - 1; $i++) 
        {
            if($i -eq 0) 
            {
                $temp = $arr[$i].Substring(1)
            }
            else
            {
                $temp = $arr[$i].Substring(2)
            }
            Write-ColorOutput white " $temp"
        }    
    }



    ## PARSE Quarantine Settings
    Write-ColorOutput white " "
    $indx = $line.IndexOf("QuarantineSettings")    
    if($indx -ge 0)
    {
        Write-ColorOutput white " "
        Write-ColorOutput yellow "QUARANTINE SETTINGS:"
        Write-ColorOutput white "--------------------"
    
        $line = $line.Substring($indx)        
        $startIndx = $line.IndexOf('{')
        $endIndx = $line.IndexOf('}')

       
        $QuarantineStr = $line.Substring($startIndx+1, $endIndx - $startIndx + 1)
        $line = $line.Substring($endIndx)          
        
        #Write-ColorOutput yellow "Quarantine settings string is -> $QuarantineStr "
                       

        $arr = $QuarantineStr.Split(',')
        $replacementStr = ""
        $replacementExists = $false
        for($i = 0; $i -lt $arr.count - 1; $i++) 
        {
            $temp = $arr[$i]
            if($i -le 2)
            {
                Write-ColorOutput white " $temp"
            }
            else
            {
                $replacementExists = $true
                $replacementStr = $replacementStr + $temp + ","               
            }
        }

        if($replacementExists -eq $true)
        {
            $temp = $replacementStr.Substring(0, $replacementStr.Length-2)
            Write-ColorOutput white " $temp"
        }          
        
    }


    ## PARSE DLP POLICIES 
    $indx = $line.IndexOf('"Policies":')    
    if($indx -ge 0)
    {

        $line = $line.Substring($indx)        
        $startIndx = $line.IndexOf('"Id"')
        $endIndx = $line.IndexOf(']')

        $PoliciesStr = $line.Substring($startIndx, $endIndx - $startIndx + 1)
        $line = $line.Substring($endIndx)        

        #Write-ColorOutput yellow "Unallowed browser string is $PoliciesStr "
        
        $arr = $PoliciesStr.Split(',')
        if($arr.count -gt 0)
        {
            Write-ColorOutput white " "
            Write-ColorOutput white " "
            Write-ColorOutput yellow "CURRENT POLICIES APPLIED:" 
            Write-ColorOutput white "------------------------"                      
        }


        foreach($aaa in $arr) 
        {
            if($aaa.contains('"Id"')) 
            {
                Write-ColorOutput white " "                
                Write-ColorOutput white "   ---------------------"                
                $aaa = $aaa.substring(1)
                Write-ColorOutput white "   $aaa"
                
            }
            elseif($aaa.contains('PolicyName')) 
            {
                Write-ColorOutput yellow "   $aaa"                                        
            }
            elseif($aaa.contains('RuleName')) 
            {
                Write-ColorOutput white "   $aaa"
                Write-ColorOutput white " "                
                
            }            
            else
            {
                if($aaa.contains('"Actions":{')) 
                {
                    $aaa = $aaa.replace('"Actions":{', '')
                    Write-ColorOutput white "   -> $aaa"                    
                }
                else
                {
                    Write-ColorOutput white "   -> $aaa"
                }
            }
        }            
    }
   
    
    if(Test-Path($CheckPolicyLogFile))
    {
        Remove-Item $CheckPolicyLogFile -Force -ErrorAction SilentlyContinue
    }

    Write-ColorOutput Cyan "POPULATE DLP POLICES COMPLETE:"    

}



###################################################################################################

### FUNCTION: FUNCTION TO POPULATE MACHINE LEVEL DLP RULES AND POLICES (PARSE REG SETTING AS JSON)

###################################################################################################

function PopulateDLPPolicies-Json($policyBodyCmd) 
{

    $params = $policyBodyCmd.paramsstr | ConvertFrom-Json	
	#$PolicyJson = $params | ConvertTo-Json -Depth 20
    $PolicyJson = $params.policy 	
    
     Write-ColorOutput Cyan "POPULATE DLP POLICES:"
   
    
    #####
    #####  SECTION 1 - Englightened apps info
    ##### 
    $enlightenedList = $PolicyJson.EnlightenedApplications
    $ItemCount = $enlightenedList.Count

     Write-ColorOutput white " "
     Write-ColorOutput yellow "ENLIGHTENED APPLICATIONS:"
     Write-ColorOutput white "--------------------------"    
 
    if($ItemCount -gt 0)
     {
       
        for($i=0; $i -lt $ItemCount; $i++){

            $CurItem = $enlightenedList.item($i)
            Write-ColorOutput white " $CurItem"

        }
     }
     else
     {
         Write-ColorOutput white " NONE"
     }


    
    #####
    #####  SECTION 2 - Unallowed apps info
    #####     
    $unallowedAppsList = $PolicyJson.UnallowedApplications
    $ItemCount = $unallowedAppsList.Count

     Write-ColorOutput white " "
     Write-ColorOutput yellow "UNALLOWED APPLICATIONS:"
     Write-ColorOutput white "--------------------------"    
 
    if($ItemCount -gt 0)
     {
       
        for($i=0; $i -lt $ItemCount; $i++){

            $CurItem = $unallowedAppsList.item($i)
            Write-ColorOutput white " $CurItem"

        }
     }
     else
     {
         Write-ColorOutput white " NONE"
     }


    #####
    #####  SECTION 3 - Unallowed browsers info
    ##### 
    $unallowedBrowsersList = $PolicyJson.UnallowedBrowsers
    $ItemCount = $unallowedBrowsersList.Count

     Write-ColorOutput white " "
     Write-ColorOutput yellow "UNALLOWED BROWSERS:"
     Write-ColorOutput white "--------------------------"    
 
    if($ItemCount -gt 0)
     {
       
        for($i=0; $i -lt $ItemCount; $i++){

            $CurItem = $unallowedBrowsersList.item($i)
            Write-ColorOutput white " $CurItem"

        }
     }
     else
     {
         Write-ColorOutput white " NONE"
     }



    #####
    #####  SECTION 4 - Cloud Apps Domain Info
    ##### 
    $CloudAppDomainsJson = $PolicyJson.CloudAppDomains
    $CloudAppDomainsList = $CloudAppDomainsJson.Domains

    Write-ColorOutput white " "
    Write-ColorOutput yellow "CLOUD APP DOMAINS INFO:"
    Write-ColorOutput white "------------------------"

    $ItemCount = $CloudAppDomainsList.Count
     if($ItemCount -gt 0)
     {       

        for($i=0; $i -lt $ItemCount; $i++){

            $CurItem = $CloudAppDomainsList.item($i)
            Write-ColorOutput white " $CurItem"

        }
     }
     else
     {
         Write-ColorOutput white " NONE"
     }
   

    #####
    #####  SECTION 5 - Unallowed Bluetooth apps info
    ##### 
    $unallowedBTList = $PolicyJson.UnallowedBluetoothApps
    $ItemCount = $unallowedBTList.Count

     Write-ColorOutput white " "
     Write-ColorOutput yellow "UNALLOWED BLUETOOTH APPS:"
     Write-ColorOutput white "--------------------------"    
 
    if($ItemCount -gt 0)
     {
       
        for($i=0; $i -lt $ItemCount; $i++){

            $CurItem = $unallowedBTList.item($i)
            Write-ColorOutput white " $CurItem"

        }
     }
     else
     {
         Write-ColorOutput white " NONE"
     }


    #####
    #####  SECTION 6 - Unallowed Cloud sync apps info
    ##### 
    $cloudSyncAppsList = $PolicyJson.UnallowedCloudSyncApps
    $ItemCount = $cloudSyncAppsList.Count

     Write-ColorOutput white " "
     Write-ColorOutput yellow "UNALLOWED CLOUD SYNC APPS:"
     Write-ColorOutput white "--------------------------"    
 
    if($ItemCount -gt 0)
     {
       
        for($i=0; $i -lt $ItemCount; $i++){

            $CurItem = $cloudSyncAppsList.item($i)
            Write-ColorOutput white " $CurItem"

        }
     }
     else
     {
         Write-ColorOutput white " NONE"
     }

    #####
    #####  SECTION 7 - Quarantine Settings Info
    ##### 
    $QuarantineSettings = $PolicyJson.QuarantineSettings
    Write-ColorOutput white " "
    Write-ColorOutput yellow "QUARANTINE SETTINGS:"
    Write-ColorOutput white "--------------------------"    
    if($QuarantineSettings -ne $null)
    {
        $a = $QuarantineSettings.EnableForCloudSyncApps
        Write-ColorOutput white "EnableForCloudSyncApps: $a"

        $a = $QuarantineSettings.QuarantinePath        
        Write-ColorOutput white "QuarantinePath: $a"

        $a = $QuarantineSettings.ShouldReplaceFile        
        Write-ColorOutput white "ShouldReplaceFile: $a"
        
        $a = $QuarantineSettings.FileReplacementText        
        Write-ColorOutput white "FileReplacementText: $a"

    }
    else
    {
        Write-ColorOutput white " NONE"
    }


    #####
    #####  SECTION 8 - DLP POLICIES 
    ##### 

    $dlpPoliciesList = $PolicyJson.Policies
    $ItemCount = $dlpPoliciesList.Count

     Write-ColorOutput white " "
     Write-ColorOutput yellow "CURRENT POLICIES APPLIED:"
     Write-ColorOutput white "--------------------------"    
 
    if($ItemCount -gt 0)
     {
       
        for($i=0; $i -lt $ItemCount; $i++){

            $CurItem = $dlpPoliciesList.item($i)

            Write-ColorOutput white " -------------------------------"      

            $a = $CurItem.Id
            Write-ColorOutput white "    Id: $a"

            $a = $CurItem.PolicyName
            Write-ColorOutput white "    PolicyName: $a"

            $a = $CurItem.RuleName
            Write-ColorOutput white "    RuleName: $a"
           
            $a = $CurItem.RequireBusinessJustificationOverride
            Write-ColorOutput white "    RequireBusinessJustificationOverride: $a"

            $a = $CurItem.PolicyTipTitleList
            Write-ColorOutput white "    PolicyTipTitleList: $a"

            $a = $CurItem.PolicyTipContentList
            Write-ColorOutput white "    PolicyTipContentList: $a"

            
            Write-ColorOutput white " "  
            Write-ColorOutput white "    Actions:"  
            
            $a = $CurItem.Actions.CopyToRemovableMedia.EnforcementMode
            Write-ColorOutput white "    -> CopyToRemovableMedia: $a"            
            $a = $CurItem.Actions.CopyToNetworkShare.EnforcementMode
            Write-ColorOutput white "    -> CopyToNetworkShare: $a"            
            $a = $CurItem.Actions.CopyToClipboard.EnforcementMode
            Write-ColorOutput white "    -> CopyToClipboard: $a"            
            $a = $CurItem.Actions.Print.EnforcementMode
            Write-ColorOutput white "    -> Print: $a"            
            $a = $CurItem.Actions.Screenclip.EnforcementMode
            Write-ColorOutput white "    -> Screenclip: $a"     
            $a = $CurItem.Actions.AccessByUnallowedApps.EnforcementMode
            Write-ColorOutput white "    -> AccessByUnallowedApps: $a"            
            $a = $CurItem.Actions.CloudEgress.EnforcementMode
            Write-ColorOutput white "    -> CloudEgress: $a"            
            $a = $CurItem.Actions.UnallowedBluetoothTransferApps.EnforcementMode
            Write-ColorOutput white "    -> UnallowedBluetoothTransferApps: $a"            
            $a = $CurItem.Actions.RemoteDesktopAccess.EnforcementMode
            Write-ColorOutput white "    -> RemoteDesktopAccess: $a"            
            
            Write-ColorOutput white " -------------------------------"      

        }
     }
     else
     {
         Write-ColorOutput white " NONE"
     }
	
}

###################################################################################################

### FUNCTION: FUNCTION TO POPULATE MACHINE LEVEL DLP Website groups (PARSE REG SETTING AS JSON)

###################################################################################################

function PopulateDLPWebsiteGroups-Json($policyBodyCmd) 
{

    $params = $policyBodyCmd.paramsstr | ConvertFrom-Json
    $PolicyJson = $params.policy

    $WebsiteGroupsList = $PolicyJson.WebsitesGroupsSettings
	
	if(![string]::IsNullOrEmpty($WebsiteGroupsList)) 
	{
		$WebsiteGroupsList = $WebsiteGroupsList | ConvertFrom-Json
		$ItemCount = $WebsiteGroupsList.Count

		if($ItemCount -gt 0)
		{
			Write-ColorOutput Cyan "POPULATE DLP WEBSITE GROUPS:"
			Write-ColorOutput white " "
			Write-ColorOutput yellow "WEBSITE GROUPS:"
			Write-ColorOutput white "--------------------------"    
 
			Write-ColorOutput white " $WebsiteGroupsList"

			for($i=0; $i -lt $ItemCount; $i++){

				$CurItem = $WebsiteGroupsList.item($i)

				Write-ColorOutput white " -------------------------------"
				Write-ColorOutput white " Group $i"

				$a = $CurItem.Id
				Write-ColorOutput white "    Id: $a"
		
				$a = $CurItem.Name
				Write-ColorOutput white "    GroupName: $a"

				$AddressesList = $CurItem.Addresses
				$AddressCount = $AddressesList.Count
			
				Write-ColorOutput white " " 
				for($iter=0; $iter -lt $AddressCount; $iter++){
			
					$CurAddr = $AddressesList.item($iter)
				
					$url = $CurAddr.Url
					if(![string]::IsNullOrEmpty($url)) {
						Write-ColorOutput white "    Url: $url"
					}
		
					$matchType = $CurAddr.MatchType
					if(![string]::IsNullOrEmpty($matchType)) {
						Write-ColorOutput white "    MatchType: $matchType"
					}
					
					$addressLower = $CurAddr.AddressLower
					if(![string]::IsNullOrEmpty($addressLower)) {
						Write-ColorOutput white "    AddressLower: $addressLower"
					}
					
					$addressUpper = $CurAddr.AddressUpper
					if(![string]::IsNullOrEmpty($addressUpper)) {
						Write-ColorOutput white "    AddressUpper: $addressUpper"
					}
					Write-ColorOutput white " " 
				}

			}
		}
		else
		{
			Write-ColorOutput white " WEBSITE GROUPS: NONE"
		}
	}

}

function ReadDlpWebsiteRules($policyName) 
{
	$path = 'HKLM:SOFTWARE\Microsoft\Windows Defender\DLP Websites\Rules'
	$result = Get-ItemPropertyValue -Path $path -Name $policyName
	$rules = [System.Text.Encoding]::Unicode.GetString( $result ) |ConvertFrom-Json

	if(![string]::IsNullOrEmpty($rules))
	{
		$WebsiteRules = $rules.dlpWebsitesRules
		$ItemCount = $WebsiteRules.Count
	
		if($ItemCount -gt 0)
		{
			Write-ColorOutput yellow "WEBSITE RULES:"
			Write-ColorOutput white "--------------------------"
		
			for($i=0; $i -lt $ItemCount; $i++){

				Write-ColorOutput white "Rule $i"
				$CurItem = $WebsiteRules.item($i)
            
				$a = $CurItem.policyRuleId
				Write-ColorOutput white "    PolicyRuleId: $a"
		
				$a = $CurItem.policyName
				Write-ColorOutput white "    PolicyName: $a"

				$a = $CurItem.ruleMode
				Write-ColorOutput white "    RuleMode: $a"
		
				$a = $CurItem.ruleName
				Write-ColorOutput white "    RuleName: $a"
				
				$Actions = $CurItem.actions
				$ActionsCount = $Actions.Count

				Write-ColorOutput white " "
				for($iter=0; $iter -lt $ActionsCount; $iter++){
			
					$CurAct = $Actions.item($iter)
					
					$WebSiteGroupId = $CurAct.webSiteGroupId
					Write-ColorOutput white "    WebSiteGroupId: $WebSiteGroupId"
					
					$RestrictionAction = $CurAct.restrictionAction
					Write-ColorOutput white "    RestrictionAction: $RestrictionAction"
					
					$Triggers = $CurAct.triggers
					$TriggerCount = $Triggers.count
					
					for($t=0; $t -lt $TriggerCount; $t++){
						
						$CurTrigger = $Triggers.item($t)
						Write-ColorOutput white "    ->$CurTrigger"
						
					}
					Write-ColorOutput white " "
				}
				Write-ColorOutput white " "
			}

			Write-ColorOutput white " -------------------------------"
		}
	}
	else
	{
		Write-ColorOutput white " WEBSITE RULES: NONE"
	}
}

############################################################################################

### FUNCTION: READ DLP POLICY FROM REG KEY ON THE DEVICE AND THEN DECOMPRESSES IT

############################################################################################

function ReadDlpPolicy($policyName)
{
    $byteArray = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection' -Name $policyName
    $memoryStream = New-Object System.IO.MemoryStream(,$byteArray)
    $deflateStream = New-Object System.IO.Compression.DeflateStream($memoryStream,  [System.IO.Compression.CompressionMode]::Decompress)
    $streamReader =  New-Object System.IO.StreamReader($deflateStream, [System.Text.Encoding]::Unicode)
    $policyStr = $streamReader.ReadToEnd()
    $policy = $policyStr | ConvertFrom-Json

    
    $policyBodyCmd = ($policy.body | ConvertFrom-Json).cmd 

    Set-Content -Path "dlppol.txt" $policyBodyCmd 
    CheckDeviceDLPPolicies("dlppol.txt")
    Write-ColorOutput White "------------------------------------"
    Write-ColorOutput White ""
    
    Write-ColorOutput White ""
    Write-ColorOutput White "------------------------------------"
    
    
    
    ## Populate all the dlp policies and rules
    <# There are two ways to to populate policies
        1. Using display tool, redirect output to a text file and finally parse the string from that text file
        2. Directly read dlp policies from registry, convert it to json string and then parse the json        
        Adding option2 and disabling/commenting option1 as maintaining option1 will be difficult as new features gets adde    
    #>

    #PopulateDLPPolicies("dlppol.txt") 
    PopulateDLPPolicies-Json($policyBodyCmd)
    PopulateDLPWebsiteGroups-Json($policyBodyCmd)	
 
}


############################################################################################

### FUNCTION: CHECKS THE BEHAVIOUR MONITOR CONFIGUREAITON 

############################################################################################

function CheckDLPPolices
{

    Write-ColorOutput Cyan "CHECK IF DLP POLICIES ARE SET ON THIS DEVICE:"
    Write-ColorOutput White " "
    
    # Dump DLP related policy information from registry
    if (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection" -Value dlpPolicy) 
    {
        ReadDlpPolicy dlppolicy
		#ReadDlpPolicy dlpSensitiveInfoTypesPolicy
	} 
    else 
    {
		Write-Coloroutput Red "    INFO: No DLP polices found in the registry of this machine"
	}
    # Dump DLP website related policy information from registry
    if (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection" -Value dlpWebSitesPolicy) 
    {
		ReadDlpPolicy dlpWebSitesPolicy
	} 
    else 
    {
		Write-Coloroutput Red "    INFO: No DLP Website groups found in the registry of this machine"
	}

    # Dump DLP website related rules information from registry
    if(-Not(Test-Path("HKLM:SOFTWARE\Microsoft\Windows Defender\DLP Websites\Rules")))
    {
        Write-ColorOutput Red "  Did not find the reg path 'SOFTWARE\Microsoft\Windows Defender\DLP Websites\Rules' 
				No website DLP website rules configured"
    }
	else 
	{
		$RegKey = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Defender\DLP Websites\Rules')

		$RegKey.PSObject.Properties | ForEach-Object {
			If($_.Name -like 'S-*')
			{
				Write-ColorOutput Cyan "POPULATE DLP WEBSITE RULES For SID:$_.Name"
				Write-ColorOutput white " "
				ReadDlpWebsiteRules $_.Name
			}
		}
	}
}




############################################################################################

### FUNCTION: CHECK IF THE BUILD IS PR SIGNED OR NOT 

############################################################################################

function CheckBuildPRSigned
{
    Write-ColorOutput Cyan "CHECK IF OS BUILD IS SIGNED OR NOT:"
    Write-ColorOutput White " "

    [string]$Sys32Path = join-path $env:windir "System32"
    $File1 = $Sys32Path + "\services.exe"
    $File2 = $Sys32Path + "\crypt32.dll"
    $File3 = $Sys32Path + "\wow64.dll"   
    $TargetFile = ""
    
    if(Test-Path($File1))
    {
        $TargetFile = $File1
    }
    
    if(($TargetFile -eq "") -and (Test-Path($File2)))
    {
        $TargetFile = $File2
    }
    if(($TargetFile -eq "") -and (Test-Path($File3)))
    {
        $TargetFile = $File3
    }



    if(($TargetFile -ne "") -and (Test-Path($TargetFile)))
    {
        
        $SignedBuild = Get-AuthenticodeSignature $TargetFile
        $SignMsg = $SignedBuild.StatusMessage
        Write-ColorOutput White "   Checking sign on file -> $TargetFile"

        
        if($SignMsg.contains("Signature verified"))
        {
            Write-ColorOutput Green "   The OS Build is signed. Looks Good"            
            
        }
        else
        {
            Write-ColorOutput Red "   The OS Build is does not seem to be signed. DLP may not work"            
            $global:bDLPMinReqOS = $false            
        }
        return
    }
    else
    {
        Write-ColorOutput Yellow "   Samples files taken from System32 does not exists. Try from Windows folder"
        Write-ColorOutput White " "
    }


    ### If can't be verified due to missing bins in System32 folder, then try few more in Windows folder
    $File1 = $env:windir + "\explorer.exe"
    $File2 = $env:windir + "\splwow64.exe"    
    $File3 = $env:windir + "\win.ini"
    $TargetFile = ""
    
    if(Test-Path($File1))
    {
        $TargetFile = $File1
    }
    
    if(($TargetFile -eq "") -and (Test-Path($File2)))
    {
        $TargetFile = $File2
    }
    if(($TargetFile -eq "") -and (Test-Path($File3)))
    {
        $TargetFile = $File3
    }


    if(($TargetFile -ne "") -and (Test-Path($TargetFile)))
    {
        Write-ColorOutput White "   Checking sign on file -> $TargetFile"
        $SignedBuild = Get-AuthenticodeSignature $TargetFile
        $SignMsg = $SignedBuild.StatusMessage
        
        if($SignMsg.contains("Signature verified"))
        {
            Write-ColorOutput Green "   The OS Build is signed. Looks Good"                    
        }
        else
        {
            Write-ColorOutput Red "   The OS Build is does not seem to be signed. DLP may not work"            
            $global:bDLPMinReqOS = $false            
        }
        return
    }
    else
    {
        Write-ColorOutput Yellow "   Samples files taken from Windows folder does not exists "
    }

    Write-ColorOutput Red "   Can't verify if Windows Build is signed or not"    

}




############################################################################################

### FUNCTION: PUTS A FINAL HELP MESSAGE 

############################################################################################

function PrintFinalMessage
{
    
    Write-ColorOutput White " "
    Write-ColorOutput Cyan "ADDITIONAL HELP NOTES:"
    Write-ColorOutput White " "    
    Write-ColorOutput Cyan "********************************************************************************************"
    Write-ColorOutput Yellow "  ==> If issues with DLP still persist after fixing all the above, follow the below steps"
    Write-ColorOutput White " "

    Write-ColorOutput White '   1. Download the MDE Client Analyzer Tool from http://aka.ms/betamdeanalyzer'
    Write-ColorOutput White '   2. Extract the downloaded zip file to any local folder'
    Write-ColorOutput White '   2. Open CMD prompt as admin in above path and run the command "MDEClientAnalyzer.cmd -t"'
    Write-ColorOutput White '   3. Reproduce the issue'
    Write-ColorOutput White '   4. Stop the trace collection'
    Write-ColorOutput White '   5. Share the created MDEClientAnalyzerResult.zip file with the DLP support team'
    Write-ColorOutput White " "
    Write-ColorOutput Cyan "*********************************************************************************************"
    Write-ColorOutput White " "
    Write-ColorOutput White " "
    
    
    Write-ColorOutput White "**********************************************************************************************"
    Write-ColorOutput Yellow "  ==> To check the extended attributes on individual files "
    Write-ColorOutput White " "
    Write-ColorOutput White '   1. Download the MDE Client Analyzer Tool from http://aka.ms/betamdeanalyzer'
    Write-ColorOutput White '   2. Extract the downloaded zip file which contains the tool DisplayExtendedAttributes.exe'
    Write-ColorOutput White '   3. Open cmd as admin and run the command "DisplayExtendedAttributes.exe <filename>"'
    Write-ColorOutput White " "
    Write-ColorOutput White "**********************************************************************************************"
    
    Write-ColorOutput White " "
    
}



function DLPMinReqFromOS
{

    ## Check if Windows Defender and Wd filter are actually running
    Write-ColorOutput White "------------------------------------"
    CheckWDRunning
    Write-ColorOutput White "------------------------------------"
    Write-ColorOutput White " " 
    Write-ColorOutput White " " 

    
    ## Get Defender Engine version.
    Write-ColorOutput White "------------------------------------"
    GetCurrentEngVersion                     
    Write-ColorOutput White "------------------------------------"
    Write-ColorOutput White " "
    Write-ColorOutput White " " 
    
    
    ## Get Defender MoCAMP version.
    Write-ColorOutput White "------------------------------------"
    GetCurrentMoCAMPVersion
    Write-ColorOutput White "------------------------------------"
    Write-ColorOutput White " " 
    Write-ColorOutput White " " 
        
    ## Check DLP feature enabled from end client
    Write-ColorOutput White "------------------------------------"
    CheckDLPEnabled
    Write-ColorOutput White "------------------------------------"
    Write-ColorOutput White " " 
    Write-ColorOutput White " " 
    
    ## Check the OS version 
    Write-ColorOutput White "------------------------------------"
    GetOSBuildNum
    Write-ColorOutput White "------------------------------------"
    Write-ColorOutput White " " 
    Write-ColorOutput White " " 


    ## Check if reg entries are present to onboard SENSE 
    ## This check is no longer needed for Public Preview phase. 
    <#
    Write-ColorOutput White "------------------------------------"
    CheckSenseOnBoardReg
    Write-ColorOutput White "------------------------------------"
    Write-ColorOutput White " " 
    Write-ColorOutput White " " 
    #>

    ## Check if BM and RTM flags are set properly
    #Write-ColorOutput White "------------------------------------"
    #CheckBMConfig
    #Write-ColorOutput White "------------------------------------"
    #Write-ColorOutput White " " 
    #Write-ColorOutput White " " 

    ## Check if BM and RTM flags are set properly under policy manager reg path
    #Write-ColorOutput White "------------------------------------"
    #CheckBMConfig_PolManager
    #Write-ColorOutput White "------------------------------------"
    #Write-ColorOutput White " " 
    #Write-ColorOutput White " " 


    ## Check if the build is PR signed
    #Write-ColorOutput White "------------------------------------"
    #CheckBuildPRSigned
    #Write-ColorOutput White "------------------------------------"
    #Write-ColorOutput White " " 
    #Write-ColorOutput White " "     
    
}


############################################################################################

### MAIN: ENTRY POINT TO THE SCRIPT

############################################################################################

try
{

    $arch = ($env:PROCESSOR_ARCHITECTURE)    # Get the OS architecture.
    
    
    ## LOGGING RELATED   
    ############################################  
    if ( -Not(Test-Path -Path $global:DLP_DIAGNOSE_LOGPATH) )
    {
        try
        {
            New-Item -Path $global:DLP_DIAGNOSE_LOGPATH -ItemType Directory | Out-Null
            Start-Sleep -s 2
            #Write-ColorOutput Yellow ("    INFO: Folder created $global:DLP_DIAGNOSE_LOGPATH")   
        }
        catch [System.Exception]
        {
            Write-ColorOutput Red  "    ERROR: Failed to create the directory: $global:DLP_DIAGNOSE_OUTPUT_LOG "
            Write-ColorOutput Yellow  "    WARN: Continuing the script without logging to a file "            
        }
    }

    [string]$OutputLogFileName = "DLPDiagnosing" + (Get-Date -Format "MMddyyyy-HHmmss").ToString() + ".log"
    #Write-ColorOutput Yellow "    File name is --> $OutputLogFileName"

    $global:LogFileName = join-path $global:DLP_DIAGNOSE_LOGPATH  $OutputLogFileName     
    #Write-ColorOutput Yellow "    File path is -->  $global:LogFileName"

    try
    {
        $logF = New-Item $global:LogFileName 
        #Write-ColorOutput Yellow "    Logging to a file started: $global:LogFileName"
    }
    catch [System.Exception]
    {
        Write-ColorOutput Red ("ERROR: Failed to create the log file. Exiting")   
        return
    }
    ############################################
        
    
    Write-ColorOutput White " "   
    Write-ColorOutput cyan "DLP Quick diagnosis ($arch) started..."


    Write-ColorOutput White " " 
    Write-ColorOutput White " " 

    ## Displays machine information 
    Write-ColorOutput White "------------------------------------"
    DisplayMachineInfo
    Write-ColorOutput White "------------------------------------"
    Write-ColorOutput White " " 
    Write-ColorOutput White " " 
    

    ## Check the mandatory requisites for DLP
    DLPMinReqFromOS

    ## If min requisites does not meet, no need of checking additional stuff
    if($global:bDLPMinReqOS -eq $false)
    {
        Write-ColorOutput Red "   ERROR: Does not meet the minimum requisites needed for DLP. Feature may not work without fixing them. Continue checking..."           
    }

    # Check if the device is part of a domain.
    Write-ColorOutput White " " 
    Write-ColorOutput White "------------------"
    Write-ColorOutput Cyan "CHECKING DOMAIN:"
    Write-ColorOutput White " " 
    [string] $machineDomain = 'Machine domain: ' + (Get-WmiObject Win32_ComputerSystem).Domain
    
    if ((gwmi win32_computersystem).partofdomain -eq $true)   
    {

        Write-ColorOutput Green "   Device is part of the domain $machineDomain"        
    }
    else
    {
        Write-ColorOutput Yellow "   Device is not part of the domain"        
    }

    Write-ColorOutput White "------------------------------------"
    Write-ColorOutput White " " 
    Write-ColorOutput White " " 

    ## Check if reg entries are present to onboard SENSE 
    Write-ColorOutput White "------------------------------------"
    CheckNotificationSettings
    Write-ColorOutput White "------------------------------------"
    Write-ColorOutput White " " 
    Write-ColorOutput White " " 


    ## Check if UX configuration settings controlled by Group Policy are set correctly for toast display
    Write-ColorOutput White "------------------------------------"
    CheckUXConfiguraitonSettings
    Write-ColorOutput White "------------------------------------"
    Write-ColorOutput White " " 
    Write-ColorOutput White " " 


    ## Check if OS back port changes have been available in this OS    
    Write-ColorOutput White "------------------------------------"
    DLPInboxChangesBackportedToOS
    Write-ColorOutput White "------------------------------------"
    Write-ColorOutput White " " 
    Write-ColorOutput White " " 

    ## Check the Office version installed on the machine
    Write-ColorOutput White "------------------------------------"
    GetOfficeVersion
    Write-ColorOutput White "------------------------------------"
    Write-ColorOutput White " " 
    Write-ColorOutput White " " 

    ## Check if Office enlightenment feature is configured
    Write-ColorOutput White "------------------------------------------"
    CheckOfficeEnlightenmentReg
    Write-ColorOutput White "------------------------------------------"
    Write-ColorOutput White " " 
    Write-ColorOutput White " "

    ## Check if DLP Website feature is configured
    Write-ColorOutput White "------------------------------------------"
    CheckDLPWebsiteReg
    Write-ColorOutput White "------------------------------------------"
    Write-ColorOutput White " " 
    Write-ColorOutput White " "
    
    ## Check if device and file polices are set properly
    Write-ColorOutput White "------------------------------------"
    CheckDLPPolices
    Write-ColorOutput White "------------------------------------"
    Write-ColorOutput White " " 
    Write-ColorOutput White " " 

    
    

    ## Check if dlp show dialog reg settings
    ## Decided not to have this check as it will be controlled by signs
    <#
    Write-ColorOutput White "------------------------------------"
    CheckDLPShowDialog
    Write-ColorOutput White "------------------------------------"
    Write-ColorOutput White " " 
    Write-ColorOutput White " " 
    #>    
    
    PrintFinalMessage
    
    
    Write-ColorOutput Cyan "DLP quick diagnosis complete"
    Write-ColorOutput White " "
    Write-Output " => Log saved at: $global:LogFileName"

}
catch [System.Exception]
{
    Write-ColorOutput Magenta $Error
}
# SIG # Begin signature block
# MIIn4wYJKoZIhvcNAQcCoIIn1DCCJ9ACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCARv5VCe4cYfAJ/
# u8sAsPZheXFWdOkAT8rmR89kUq4KtKCCDZcwggYVMIID/aADAgECAhMzAAADEBr/
# fXDbjW9DAAAAAAMQMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjIwODA0MjAyNjM5WhcNMjMwODAzMjAyNjM5WjCBlDEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjE+MDwGA1UEAxM1TWlj
# cm9zb2Z0IFdpbmRvd3MgRGVmZW5kZXIgQWR2YW5jZWQgVGhyZWF0IFByb3RlY3Rp
# b24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0y67idUrLERDl3ls1
# 1XkmCQNGqDqXUbrM7xeQ3MDX2TI2X7/wxqqVBo5wjSGMUEUxZpgrQRj7fyyeQWvy
# OKx7cxcBYXxRWjOQRSYWqk+hcaLj7E9CkuYyM1tuVxuAehDD1jqwLGS5LfFG9iE9
# tXCQHI59kCLocKMNm2C8RWNNKlPYN0dkN/pcEIpf6L+P+GXYN76jL+k7uXY0Vgpu
# uKvUZdxukyqhYbWy8aNr8BasPSOudq2+1VzK52kbUq79M7F3lN+JfDdyiG5YoSdc
# XDrvOU1fnP1Kc4PtUJL7tSHFuBylTiNyDnHfSORQeZPFg971CeZS7I8ZFojDLgTY
# kDQDAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBggrBgEFBQcDAwYKKwYBBAGCN0wv
# ATAdBgNVHQ4EFgQU0X7BWbJmeu82AxuDs7MBJC8zJ8swRQYDVR0RBD4wPKQ6MDgx
# HjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEWMBQGA1UEBRMNNDUxODk0
# KzQ3MjIyMDAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzcitW2oynUClTBUBgNVHR8E
# TTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9N
# aWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEGCCsGAQUFBwEBBFUwUzBR
# BggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0
# cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0MAwGA1UdEwEB/wQCMAAw
# DQYJKoZIhvcNAQELBQADggIBAIXZp9/puv2exE6jflkfuJ3E8xrXA1ch9bnCloXS
# 01xOXTauGU/+1peumenJbgwCzn/iwGIJkuoHSx5F85n7OG9InPRApTNcYmAkGPIk
# /x5SNl67Su8eHlLGd8erjoEcseZBckRENr5mBHtELtOWR80cAH9dbALlY/gJ5FDq
# jOxA9Q6UDeaT9oeIJwSy/LD9sUKrUZ4zSvqFBjjEBx3g2TfmRe3qLfKJEOL1mzCk
# 06RHYwcU2uU1s5USCeePuafeQ159io+FVdW5f7703UeD4pzXOp4eZTtWl0875By+
# bWxAR8/dc41v2MEQoy0WplbGfkBm9BWT0w0pL3itBYcXRlzIfPForBPK2aIQOMPL
# CH8JR3uJXvbTJ5apXBAFOWl6dU1JqGTT/iuWsVznHBqDmq6zKf38QYocac0o7qL3
# RG1/eiQdbPQisNpFiqTzTd6lyUaXrPtk+BniKT4bVXJ2FrfsmLiXIcFhC6FAidok
# spWZVHS8T4WwSPVpmhjEgubZlhldva/wOT/OjtGzoy6L7yNKjcSadVou4VroLLK9
# qwYgKnjyzX8KEcGkKUXScwZIp8uWDp5bmKYh+5SQEa26bzHcX0a1iqmsUoP5JhYL
# xwloQM2AgY9AEAIHSFXfCo17ae/cxV3sEaLfuL09Z1sSQC5wm32hV3YyyEgsRDXE
# zXRCMIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkqhkiG9w0BAQsFADCBiDEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWlj
# cm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTEwHhcNMTEwNzA4
# MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBD
# QSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAq/D6chAcLq3Y
# bqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03a8YS2AvwOMKZBrDIOdUB
# FDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akrrnoJr9eWWcpgGgXpZnbo
# MlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0RrrgOGSsbmQ1eKagYw8t00CT
# +OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy4BI6t0le2O3tQ5GD2Xuy
# e4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9sbKvkjh+0p2ALPVOVpEh
# NSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAhdCVfGCi2zCcoOCWYOUo2
# z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8kA/DRelsv1SPjcF0PUUZ3
# s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTBw3J64HLnJN+/RpnF78Ic
# V9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmnEyimp31ngOaKYnhfsi+E
# 11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90lfdu+HggWCwTXWCVmj5P
# M4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0wggHpMBAGCSsGAQQBgjcV
# AQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2oynUClTAZBgkrBgEEAYI3
# FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAf
# BgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBaBgNVHR8EUzBRME+gTaBL
# hklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNS
# b29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsGAQUFBwEBBFIwUDBOBggr
# BgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNS
# b29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNVHSAEgZcwgZQwgZEGCSsG
# AQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsGAQUFBwICMDQeMiAdAEwA
# ZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABlAG0AZQBuAHQALiAdMA0G
# CSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKbC5YR4WOSmUKWfdJ5DJDB
# ZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11lhJB9i0ZQVdgMknzSGksc
# 8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6I/MTfaaQdION9MsmAkYq
# wooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0wI/zRive/DvQvTXvbiWu
# 5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560STkKxgrCxq2u5bLZ2xWI
# UUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQamASooPoI/E01mC8CzTfXh
# j38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGaJ+HNpZfQ7l1jQeNbB5yH
# PgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ahXJbYANahRr1Z85elCUtI
# EJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA9Z74v2u3S5fi63V4Guzq
# N5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33VtY5E90Z1WTk+/gFcioXgR
# MiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQ
# zTGCGaIwghmeAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEC
# EzMAAAMQGv99cNuNb0MAAAAAAxAwDQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcN
# AQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUw
# LwYJKoZIhvcNAQkEMSIEIFUeMxgIk8X8uItrfB2bUIevB1vsOoCG1jh4mFWET2ek
# MEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEBBQAEggEATd/fQNnCfd5e
# Af2QgporBYi7D6EqHIv8ZcqBhQy4MuJeomfceczZ/GNSnS/uQqu3gyeoXL75vppq
# Ltm83z7/mExuMWhUHu3AW6zt5K/+hE5DR7IgvtEbFS5rqM3Kv9o7yWA2mtFVdNPU
# tZ7dYEOfE72q0tl16K9PTVzdQjgoQyMYKDnNpnQMHeRXtpLhugfe+N37TC0DLq5A
# iH3QsrXWBNmushxl+gdWhUT2pBuspHvSvqNOLITebkwuL8u62HfcbL76JhzIjj7x
# oYqhDC80ytLz6x+SwZ3TKFaNWqS4Y0Bt14r6Uc4OC26deUZ75tkIPRzFMXPs00YE
# 6xQbPYGFaKGCFywwghcoBgorBgEEAYI3AwMBMYIXGDCCFxQGCSqGSIb3DQEHAqCC
# FwUwghcBAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFZBgsqhkiG9w0BCRABBKCCAUgE
# ggFEMIIBQAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUABCDICLXwnMMK
# bpe7CrrbXRQj7WSop72QM+sQt0c4yTAS5QIGY0/0j8d3GBMyMDIyMTAyNjA3NTcy
# NC41NzRaMASAAgH0oIHYpIHVMIHSMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25z
# IExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjNCRDQtNEI4MC02OUMz
# MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloIIRezCCBycw
# ggUPoAMCAQICEzMAAAG0+4AIRAXSLfoAAQAAAbQwDQYJKoZIhvcNAQELBQAwfDEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWlj
# cm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjIwOTIwMjAyMjA5WhcNMjMx
# MjE0MjAyMjA5WjCB0jELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVk
# MSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjozQkQ0LTRCODAtNjlDMzElMCMGA1UE
# AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBALRHpp5lBzJCH7zortuyvOmW8FoZLBsFe9g5dbhnaq9q
# Spvpn86E/mJ4JKvWixH/lw7QA8gPtiiGVNIjvFhu/XiY889vX5WaQSmyoPMZdj9z
# vXa5XrkMN05zXzTePkCIIzF6RN7cTxezOyESymTIjrdxX5BVlZolyQAOxNziMCYK
# YYNPbYd0786fDE/PhzrRt23a0Xf8trvFa0LEEy2YlcE2eqg2CjU/D0GZe8Ra0kjt
# 0M12vdS4qWZ2Dpd7IhiQwnntQWu19Ytd3UBR8SpeRX+Ccw3bjgWfOXtla6chctWt
# 2shlMwayMOfY4TG4yMPWFXELfZFFp7cgpjZNeVsmwkvoV6RAwy1Y9V+VvbJ5qFta
# rtN/rp6a0I1kGlbjuwX3L0HTVXcikqgHistXk9h3HOZ9WgFXlxZurG1SZmcz0BEE
# dya+1vGHE45KguYU9qq2LiHGBjn9z4+DqnV5tUKobsLbJMb4r+8st2fj8SacSsft
# nusxkWqEJiJS34P2uNlzVR03+ls6+ZO0NcO79LgP7BbIMipiOx8yh19PMQw0piaK
# FwOW7Q+gdJcfy6rOkG+CrYZwOzdiBHSebIzCIch2cAa+38w7JFP/koKdlJ36qzdV
# XWv4G/qZpWycIvDKYbxJWM40+z2Stg5uHqK3I8e09kFXtxCHpS7hm8c8m25WaEU5
# AgMBAAGjggFJMIIBRTAdBgNVHQ4EFgQUy0SF5fGUuDqcuxIot07eOMwy2X4wHwYD
# VR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZO
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIw
# VGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBc
# BggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0
# cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQwDAYD
# VR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAOBgNVHQ8BAf8EBAMC
# B4AwDQYJKoZIhvcNAQELBQADggIBABLRDwWMKbeCYqEqtI6Bs8KmF+kqDR+2G6qY
# AK3ZZ63bert7pCkRJbihFaktl2o18cdFJFxnOF4vXadm0sabskJ05KviEMJIO6dX
# Sq8AGtr3Zmjc895q0mnlBLuNMgk4R8KrkJMHqBuHqkUWXtfTrVUpgwzQt2UOiINK
# s+/b4r14MuXRVpOJ6cQOS8UhkeMAWl2iLlYaBGtOr3f/f9mLEPfWwoke0sSUbdV6
# 0OZCRh1ItBYYM9efKr14H5qu6jan6n00prEEa7W3uGb/1/qj6P5emnvkqy5HI0X6
# 9DjVdLxVbjSsegm/dA+S4DaXPcfFf6iBxK/iV21l1upgEVVajUApl5VR40wY4XF8
# EpmnUdTqLXDf7CqdhDjPST2K/OjvWPyQGQvc7oPapYyk66GU32AOyyHXJj6+vbtR
# Ug/+ory+h0R2Xf5NhC+xbWcMzXEUXRRf1YKZDsRyH6r412pm8KDKE/r7Rk7aoKK7
# oYUpNGzNRf6QaYv5z2bVTSxkzWivFrepLHGwvRun9PYM/8AQSTgZr0yzzjk/97Wg
# hkqCaAwAVpyvg3uaYnuCl/AccSkGyb8c+70bFSeUephsfgb2r+QI7Mb2WcOnkJpC
# NLz0XJMS/UwlQn1ktLsiCpsqOk3aLJ2wTv6LK3u69I0vQB/LKRKlZYRXKUDXzoPw
# r3UtsTVTMIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG
# 9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
# BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEy
# MDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIw
# MTAwHhcNMjEwOTMwMTgyMjI1WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBQQ0EgMjAxMDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
# AOThpkzntHIhC3miy9ckeb0O1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az
# /1xPx2b3lVNxWuJ+Slr+uDZnhUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V2
# 9YZQ3MFEyHFcUTE3oAo4bo3t1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oa
# ezOtgFt+jBAcnVL+tuhiJdxqD89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkN
# yjYtcI4xyDUoveO0hyTD4MmPfrVUj9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7K
# MtXAhjBcTyziYrLNueKNiOSWrAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRf
# NN0Sidb9pSB9fvzZnkXftnIv231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SU
# HDSCD/AQ8rdHGO2n6Jl8P0zbr17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoY
# WmEBc8pnol7XKHYC4jMYctenIPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5
# C4lh8zYGNRiER9vcG9H9stQcxWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8
# FdsaN8cIFRg/eKtFtvUeh17aj54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TAS
# BgkrBgEEAYI3FQEEBQIDAQABMCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1
# Kc8Q/y8E7jAdBgNVHQ4EFgQUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUw
# UzBRBgwrBgEEAYI3TIN9AQEwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNy
# b3NvZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoG
# CCsGAQUFBwMIMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIB
# hjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fO
# mhjEMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9w
# a2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggr
# BgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNv
# bS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3
# DQEBCwUAA4ICAQCdVX38Kq3hLB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEz
# tTnXwnE2P9pkbHzQdTltuw8x5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJW
# AAOwBb6J6Gngugnue99qb74py27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G
# 82jfZfakVqr3lbYoVSfQJL1AoL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz/Aye
# ixmJ5/ALaoHCgRlCGVJ1ijbCHcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI9
# 5ko+ZjtPu4b6MhrZlvSP9pEB9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1j
# dEgssU5HLcEUBHG/ZPkkvnNtyo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZ
# KCS6OEuabvshVGtqRRFHqfG3rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xB
# Zj1p/cvBQUl+fpO+y/g75LcVv7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuP
# Ntq6TPmb/wrpNPgkNWcr4A245oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvp
# e784cETRkPHIqzqKOghif9lwY1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAtcw
# ggJAAgEBMIIBAKGB2KSB1TCB0jELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBM
# aW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjozQkQ0LTRCODAtNjlDMzEl
# MCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsO
# AwIaAxUAZZzYkPObl/ZzeCkSbf4B5CceCQiggYMwgYCkfjB8MQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOcDBHkwIhgPMjAyMjEw
# MjYwODU3MjlaGA8yMDIyMTAyNzA4NTcyOVowdzA9BgorBgEEAYRZCgQBMS8wLTAK
# AgUA5wMEeQIBADAKAgEAAgIEBgIB/zAHAgEAAgIT9TAKAgUA5wRV+QIBADA2Bgor
# BgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAID
# AYagMA0GCSqGSIb3DQEBBQUAA4GBAIsSnpD0XqS7bdxsYCXP9t8ZIjyEbsSi32Q5
# Nz3IFUDNwLs/VMEc/ZpLliBeK4SAsHn+0o8bw6iDsBxhF8MneaBJtbqvI0AVCpPD
# gmUrZr4QT1j+1hgHV7InNkglzj2FlhAA+zGEvEdOwAPJVhr1p8yHcDi/wLkktbxz
# PJR2Ko0wMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIw
# MTACEzMAAAG0+4AIRAXSLfoAAQAAAbQwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqG
# SIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgSnVHfRgOUvPQ
# pf+bQKuNmQCePM1rX/JrDbsmYvrLIjgwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHk
# MIG9BCDTyPd75qMwcAZRcb36/6xJa3hT0eLse71ysdp4twH3BjCBmDCBgKR+MHwx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1p
# Y3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABtPuACEQF0i36AAEAAAG0
# MCIEINwt2+7RQt9l6zAYc25pFNGPNJdEtg8pXeTsm66UW73fMA0GCSqGSIb3DQEB
# CwUABIICAJPCbcmgJfOACZDIiPtiiHLs9DUWihfN+WkgRFBZJhkAKbcCg9Tl5/6a
# c/FVmHROX0jjxi0O0drOq70vXCSlvI3HNmLeUVH7sPAWVji6LdDAVUzrQyo8pDP4
# 826xWvh+0TC47yJYgm8cPAjVSG5mJwX0fIsE+za0e8dpyPwqXKcIcLrI7pStimlO
# z18I8yTjMYhf5eoLFAzUFlUcVmo7fYPuBjAVzxKQgm0kx2FxBU3vCWULLbJ5+QHP
# UyFUZUCgo3B1D/Ua8Dlf4ITNkEWN8KLuf7TaizVLuBShYskXogHjhQdeJcIst0rv
# AHs2i/weSZoXAIecQZ17QmMAlX1vXsiz8V/ktW0zbqTp3nyEEJNtKWXbTN/S63eq
# shfDTOPxAac4rPjG0d+hYiL42ayywMNkn0CXD8twsjH2y2Yv8Bk0BVLdsZ6SfJTA
# ZcAujrXmMOYt9Y/MjDck4Bwb5PZiJ86iCXGAJhTS1nR9G0jHNqF57WPQ2xE68/MK
# Vkxf20TDelsjygvEPfcCZs4sAIeCF6iTpyhzFFk2aR04ysVu1dRL9Ouh+69P+45X
# eyZ+mrENNYliWA5mQYFTehFVBDDPJ2LjmFkW2vgOYStD6hrIuMDTSWwhNJELPaHb
# SZwsv2mJVJZDrspmHs0MBKlz47hNexciyvl999DciGQOm5quqkIc
# SIG # End signature block
