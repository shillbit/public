<#
.SYNOPSIS
 
.NOTES
    Author: MDE OPS Team
    Date/Version: See $ScriptVer
#>
param (
	[string]$outputDir = $PSScriptRoot, 
	## To collect netsh traces -n 
	[Alias("n")][switch]$netTrace,
	[Alias("w", "wfp")][switch]$wfpTrace,
	##To collect Sense performance traces '-l' or '-h'
	[Alias("l")][switch]$wprpTraceL,
	[Alias("h")][switch]$wprpTraceH,
	##To collect Sense app compatibility traces '-c'
	[Alias("c")][switch]$AppCompatC,
	##To collect Sense dumps '-d'
	[Alias("d")][switch]$CrashDumpD,
	##To collect traces for isolation issues '-i'
	[Alias("i")][switch]$NetTraceI,
	##To collect boot traces issues at startup '-b'
	[Alias("b")][switch]$BootTraceB,
	##To collect traces for WD AntiVirus pref issues '-a'
	[Alias("a")][switch]$WDPerfTraceA,
	##To collect verbose traces for WD AntiVirus issues '-v'
	[Alias("v")][switch]$WDVerboseTraceV,
	##To collect verbose traces for DLP issues '-t'
	[Alias("t")][switch]$DlpT,
	##To collect quick DLP Diagnose run '-q'
	[Alias("q")][switch]$DlpQ,
	##To prepare the device for full dump collection '-z'
	[Alias("z")][switch]$FullCrashDumpZ,
	##To set the device for remote data collection '-r'
	[Alias("r")][switch]$RemoteRun,
	##To set the minutes to run for data collection '-m'
	[Alias("m")][int]$MinutesToRun = "5",
	##To crash the device and create a memory dump immediately '-k'
	[Alias("K")][switch]$NotMyFault
)

# Global variables
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8  # MDEClientAnalyzer.exe outputs UTF-8, so interpret its output as such
$ProcessWaitMin = 5	# wait max minutes to complete
$ToolsDir = Join-Path $outputDir "Tools"
$buildNumber = ([System.Environment]::OSVersion).Version.build
#Enforcing default PSModulePath to avoid getting unexpected modules to run instead of built-in modules
$env:PSModulePath = "C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules"

# Define outputs
$resultOutputDir = Join-Path $outputDir "MDEClientAnalyzerResult"
$SysLogs = Join-Path $resultOutputDir "SystemInfoLogs"
$psrFile = Join-Path $resultOutputDir "Psr.zip"
$ProcMonlog = Join-Path $resultOutputDir "Procmonlog.pml"
$connectivityCheckFile = Join-Path $SysLogs "MDEClientAnalyzer.txt"
$connectivityCheckUserFile = Join-Path $SysLogs "MDEClientAnalyzer_User.txt"
$outputZipFile = Join-Path $outputDir "MDEClientAnalyzerResult.zip"
$WprpTraceFile = Join-Path  $resultOutputDir "FullSenseClient.etl"
$XmlLogFile = Join-Path $SysLogs "MDEClientAnalyzer.xml"
$XslFile = Join-Path $ToolsDir "MDEReport.xslt"
$RegionsJson = Join-Path $ToolsDir "RegionsURLs.json"
$EndpointList = Join-Path $ToolsDir "endpoints.txt"
$ResourcesJson = Join-Path $ToolsDir "Events.json"
$HtmOutputFile = Join-Path $resultOutputDir "MDEClientAnalyzer.htm"
$CertSignerResults = "$resultOutputDir\SystemInfoLogs\CertSigner.log"
$CertResults = "$resultOutputDir\SystemInfoLogs\CertValidate.log"

$OSPreviousVersion = $false
$AVPassiveMode = $false
$ScriptVer = "23102022"
$AllRegionsURLs = @{}

# function to read Registry Value
function Get-RegistryValue {
	param (
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]$Path,
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]$Value
	)

	if (Test-Path -path $Path) {
		return Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Value -ErrorAction "SilentlyContinue"
	}
 else {
		return $false
	}
}

# This telnet test does not support proxy as-is
Function TelnetTest($RemoteHost, $port) { 
	[int32]$TimeOutSeconds = 10000
	Try {
		$tcp = New-Object System.Net.Sockets.TcpClient
		$connection = $tcp.BeginConnect($RemoteHost, $Port, $null, $null)
		$connection.AsyncWaitHandle.WaitOne($TimeOutSeconds, $false)  | Out-Null 
		if ($tcp.Connected -eq $true) {
			$ConnectionResult = "Successfully connected to Host: $RemoteHost on Port: $Port"
		}
		else {
			$ConnectionResult = "Could not connect to Host: $RemoteHost on Port: $Port"
		}
	} 
	Catch {
		$ConnectionResult = "Unknown Error"
	}
	return $ConnectionResult
}


function Write-ReportEvent($severity, $id, $category, $check, $checkresult, $guidance) { 
	$checkresult_txtfile = [regex]::replace($checkresult, '<br>', '')
	$guidance_txtfile = [regex]::replace($guidance, '<br>', '')
	# Write Message to the screen
	$descLine = ((Get-Date).ToString("u") + " [$severity]" + " $check" + " $id" + ": " + $checkresult_txtfile + " " + $guidance_txtfile )
	if ($severity -eq "Error") {
		Write-Host -BackgroundColor Red -ForegroundColor Yellow $descLine
	}
 elseif ($severity -eq "Warning") {
		Write-Host -ForegroundColor Yellow $descLine
	}
 else {
		Write-Host $descLine
	}
	# Write message to the ConnectivityCheckFile
	$descLine | Out-File $connectivityCheckFile -append

	# Write Message to XML
	$subsectionNode = $script:xmlDoc.CreateNode("element", "event", "")
	$subsectionNode.SetAttribute("id", $id)

	$eventContext1 = $script:xmlDoc.CreateNode("element", "severity", "")
	$eventContext1.psbase.InnerText = $severity

	$eventContext2 = $script:xmlDoc.CreateNode("element", "category", "")
	$eventContext2.psbase.InnerText = $category

	$eventContext3 = $script:xmlDoc.CreateNode("element", "check", "")
	$eventContext3.psbase.InnerText = $check

	$eventContext4 = $script:xmlDoc.CreateNode("element", "checkresult", "")
	$eventContext4.psbase.InnerText = $checkresult

	$eventContext5 = $script:xmlDoc.CreateNode("element", "guidance", "")
	$eventContext5.psbase.InnerText = $guidance

	$subsectionNode.AppendChild($eventContext1) | out-Null
	$subsectionNode.AppendChild($eventContext2) | out-Null
	$subsectionNode.AppendChild($eventContext3) | out-Null
	$subsectionNode.AppendChild($eventContext4) | out-Null
	$subsectionNode.AppendChild($eventContext5) | out-Null
    
	$xmlRoot = $script:xmlDoc.SelectNodes("/MDEResults")
	$InputNode = $xmlRoot.SelectSingleNode("events")
	$InputNode.AppendChild($subsectionNode) | Out-Null
}
<#
function Write-Report($section, $subsection, $value, $DisplayName) {  
	$subsectionNode = $script:xmlDoc.CreateNode("element", $subsection, "")    
	$subsectionNode.SetAttribute("displayName", $DisplayName)
	$subsectionNode.psbase.InnerText = $value

	$checkresult = $DisplayName + ": " + $Value
	# Write message to the ConnectivityCheckFile
	$checkresult | Out-File $connectivityCheckFile -append

	$xmlRoot = $script:xmlDoc.SelectNodes("/MDEResults")
	$InputNode = $xmlRoot.SelectSingleNode($section)
	$InputNode.AppendChild($subsectionNode) | Out-Null
}
#>

function Write-Report($section, $subsection, $displayName, $value, $alert) { 
	$subsectionNode = $script:xmlDoc.CreateNode("element", $subsection, "")    
	$subsectionNode.SetAttribute("displayName", $displayName)

	$eventContext1 = $script:xmlDoc.CreateNode("element", "value", "")
	$eventContext1.psbase.InnerText = $value
	$subsectionNode.AppendChild($eventContext1) | out-Null

	if ($value -eq "Running") {
		$alert = "None"
	} elseif (($value -eq "Stopped" -or $value -eq "StartPending")) {
		$alert = "High"
	}

	if ($alert) {
		$eventContext2 = $script:xmlDoc.CreateNode("element", "alert", "")
		$eventContext2.psbase.InnerText = $alert
		$subsectionNode.AppendChild($eventContext2) | out-Null
	}

	$checkresult = $DisplayName + ": " + $value
	# Write message to the ConnectivityCheckFile
	$checkresult | Out-File $connectivityCheckFile -append

	$xmlRoot = $script:xmlDoc.SelectNodes("/MDEResults")
	$InputNode = $xmlRoot.SelectSingleNode($section)
	$InputNode.AppendChild($subsectionNode) | Out-Null
}


# Initialize XML log - for consumption by external parser
function InitXmlLog {
	$script:xmlDoc = New-Object System.Xml.XmlDocument								 
	$script:xmlDoc = [xml]"<?xml version=""1.0"" encoding=""utf-8""?><MDEResults><general></general><devInfo></devInfo><EDRCompInfo></EDRCompInfo><MDEDevConfig></MDEDevConfig><AVCompInfo></AVCompInfo><events></events></MDEResults>"
}

function Format-XML ([xml]$xml) {
	$StringWriter = New-Object System.IO.StringWriter
	$XmlWriter = New-Object System.XMl.XmlTextWriter $StringWriter
	$xmlWriter.Formatting = [System.Xml.Formatting]::Indented
	$xml.WriteContentTo($XmlWriter)
	Write-Output $StringWriter.ToString()
}

function ShowDlpPolicy($policyName) {
	$byteArray = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection' -Name $policyName
	$memoryStream = New-Object System.IO.MemoryStream(, $byteArray)
	$deflateStream = New-Object System.IO.Compression.DeflateStream($memoryStream, [System.IO.Compression.CompressionMode]::Decompress)
	$streamReader = New-Object System.IO.StreamReader($deflateStream, [System.Text.Encoding]::Unicode)
	$policyStr = $streamReader.ReadToEnd()
	$policy = $policyStr | ConvertFrom-Json
	$policyBodyCmd = ($policy.body | ConvertFrom-Json).cmd
	$policyBodyCmd | Format-List -Property hash, type, cmdtype, id, priority, timestamp, enforce | Out-File "$resultOutputDir\DLP\$policyName.txt"

	$timestamp = [datetime]$policyBodyCmd.timestamp
	"Timestamp: $($timestamp.ToString('u'))" | Out-File "$resultOutputDir\DLP\$policyName.txt" -Append

	# convert from/to json so it's JSON-formatted
	if ($policyBodyCmd.data) {
		$params = $policyBodyCmd.data | ConvertFrom-Json
	} elseif ($policyBodyCmd.paramsstr) {
		$params = $policyBodyCmd.paramsstr | ConvertFrom-Json
	}
	$params | ConvertTo-Json -Depth 20 > "$resultOutputDir\DLP\$policyName.json"

	if ($params.SensitiveInfoPolicy) {
		foreach ($SensitiveInfoPolicy in $params.SensitiveInfoPolicy) {
			$configStr = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($SensitiveInfoPolicy.Config))
			$config = [xml]$configStr
			Format-XML $config | Out-File "$resultOutputDir\DLP\rule_$($SensitiveInfoPolicy.RulePackageId).xml"
		}
	}
}

function PromptForDLPFile() {
	while ($true) {
		Write-Host -ForegroundColor Green "Please enter the full path to the document that was used during log collection. For example C:\Users\John Doe\Desktop\report.docx"
		[string]$DLPFilePath = (Read-Host)
		if ($DLPFilePath.Length -gt 0) {
			# Handle error cases
			try {
				if ((Test-Path -path ($DLPFilePath -Replace '"', "") -PathType leaf)) {
					return $DLPFilePath
				}
			}
			catch {
				Write-Host "Path is not pointing to a valid file. Exception: $_"
				return $DLPFilePath = $false
			}
		}
		else {
			Write-Host "Empty path was provided"
			return $DLPFilePath = $false
		}

	}
}

function Get-DLPEA {
	if ($DlpT) {
		New-Item -ItemType Directory -Path "$resultOutputDir\DLP" -ErrorAction SilentlyContinue | out-Null
		$DisplayEA = Join-Path $ToolsDir "DisplayExtendedAttribute.exe"
		CheckAuthenticodeSignature $DisplayEA
		$DLPFilePath = $false
		if (!($system -or $RemoteRun)) {
			do {
				$DLPFilePath = PromptForDLPFile
			} while ($DLPFilePath -eq $false)
			Write-Host "Checking Extended Attributes for $DLPFilePath..."
			"Extended attributes for: $DLPFilePath`n" | out-File -Encoding UTF8 "$resultOutputDir\DLP\FileEAs.txt"
			CheckAuthenticodeSignature $DisplayEA
			&$DisplayEA "$DLPFilePath" | out-File -encoding UTF8 -Append "$resultOutputDir\DLP\FileEAs.txt"
		}
	}
}

function Test-WPRError($ExitCode) {
	if (($ExitCode -eq "0") -or ($ExitCode -eq "-984076288")) {
		# -984076288 = There are no trace profiles running.
		return
	} elseif ($ExitCode -eq "-2147023446") {
		# 2147023446 = Insufficient system resources exist to complete the requested service.
		Check-Command-verified "logman.exe"
		[int]$ETSCount = (&logman.exe query -ets).count | Out-File $connectivityCheckFile -Append
		[string]$ETSSessions = (&logman.exe query -ets) | Out-File $connectivityCheckFile -Append
		Write-error "Starting WPR trace has failed because too many trace sessions are already running on this system." | Out-File $connectivityCheckFile -Append
		Write-Warning "If this is the first time you are seeing this error, try restarting the machine and collecting traces from scratch."
		$ETSCount | Out-File $connectivityCheckFile -Append
		$ETSSessions | Out-File $connectivityCheckFile -Append
		Write-Host "Proceeding anyway without the collection of advanced traces..."
	} else {
		"Error $ExitCode occured when starting WPR trace." | Out-File $connectivityCheckFile -Append
	}
}

function Set-BootTrace {
	$ProcmonCommand = Join-Path $ToolsDir "Procmon.exe"
	Write-Host "Checking if WPR Boot trace is already running"
	$WptState = Test-WptState
	if ((!$OSPreviousVersion) -and ($WptState -eq "Ready")) {
		Check-Command-verified "wpr.exe"
		$StartWPRCommand = Start-Process -PassThru -wait -WindowStyle minimized wpr.exe -ArgumentList "-boottrace -stopboot `"$WprpTraceFile`""
		Test-WPRError $StartWPRCommand.ExitCode
	}
	Write-Host "Saving any running ProcMon Boot trace"
	CheckAuthenticodeSignature $ProcmonCommand
	Start-Process -PassThru -wait $ProcmonCommand -ArgumentList "-AcceptEula -ConvertBootLog `"$ProcMonlog`"" | Out-Null
	$procmonlogs = Get-Item "$resultOutputDir\*.pml"
	if ($procmonlogs -eq $null) {
		CheckAuthenticodeSignature $ProcmonCommand
		& $ProcmonCommand -AcceptEula -EnableBootLogging -NoFilter -quiet -minimized
		if ((!$OSPreviousVersion) -and ($WptState -eq "Ready")) {
			Check-Command-verified "wpr.exe"
			$StartWPRCommand = Start-Process -PassThru -wait -WindowStyle minimized wpr.exe -ArgumentList "-boottrace -addboot `"$ToolsDir\Sense.wprp`" -filemode"
			Test-WPRError $StartWPRCommand.ExitCode
		}
		Write-Host "Boot logging ready"
		Write-Host -BackgroundColor Red -ForegroundColor Yellow "Please run the tool again with '-b' parameter when the device is back online" 
		if ($RemoteRun) {
			Write-Warning "Restarting remote device..."
		}
		else {
			Read-Host "Press ENTER when you are ready to restart..."
		}
		Restart-Computer -ComputerName . -Force
	}
	else {
		Write-Host "Boot logs were collected successfully"
		Get-Log
	}
}

function Set-FullCrashDump {
	Set-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -name CrashDumpEnabled -Type DWord -Value "1"
	Write-Host "Registry settings for full dump collection have been configured"
}

function Set-CrashOnCtrlScroll {
	Set-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Services\i8042prt\Parameters' -name CrashOnCtrlScroll -Type DWord -Value "1"
	Set-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Services\kbdhid\Parameters' -name CrashOnCtrlScroll -Type DWord -Value "1"
	Set-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Services\hyperkbd\Parameters' -name CrashOnCtrlScroll -Type DWord -Value "1" -ErrorAction SilentlyContinue
	Write-Host "Registry settings for CrashOnCtrlScroll have been configured as per https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/forcing-a-system-crash-from-the-keyboard"
}

function Start-PSRRecording {
	if ($RemoteRun) {
		"`r`nSkipping PSR recording as it requires an interactive user session." | Out-File $connectivityCheckFile -Append
	} 
	else {
		Check-Command-verified "psr.exe"
		& psr.exe -stop
		Start-Sleep -Seconds 2
		Check-Command-verified "psr.exe"
		& psr.exe -start -output "$psrFile" -gui 0 -maxsc 99 -sc 1
	}
}

function Stop-PSRRecording {
	if ($RemoteRun) {
		"`r`nSkipping PSR recording as it requires an interactive user session." | Out-File $connectivityCheckFile -Append
	} 
	else {
		Check-Command-verified "psr.exe"
		& psr.exe -stop
	}
}

function Start-MDAVTrace {
	if ((!$OSPreviousVersion) -or ($MDfWS)) {
		if (($NetTraceI) -and (!$DlpT) -and (!$WDVerboseTraceV)) {
			CheckAuthenticodeSignature $MpCmdRunCommand
			Start-Process -WindowStyle minimized $MpCmdRunCommand -WorkingDirectory $CurrentMpCmdPath.ToString() -ArgumentList "-trace -grouping 0x1B -level 0x3F"
		}
		elseif ($DlpT) {
			CheckAuthenticodeSignature $MpCmdRunCommand
			Start-Process -WindowStyle minimized $MpCmdRunCommand -WorkingDirectory $CurrentMpCmdPath.ToString() -ArgumentList "-trace -grouping 0x309 -level 0x3F"
		}
		elseif ($WDVerboseTraceV) {
			CheckAuthenticodeSignature $MpCmdRunCommand
			Start-Process -WindowStyle minimized $MpCmdRunCommand -WorkingDirectory $CurrentMpCmdPath.ToString() -ArgumentList "-trace -grouping 0x1FF -level ff"
			&$MpCmdRunCommand -CaptureNetworkTrace -path C:\Users\Public\Downloads\Capture.npcap | Out-File $connectivityCheckFile -Append
			Start-WinEventDebug Microsoft-Windows-SmartScreen/Debug
		}
		if ($WDPerfTraceA) {
			$WPRP = Join-Path $ToolsDir "WD.WPRP"
			Write-Host "Starting WD perf trace"
			Check-Command-verified "wpr.exe"
			$StartWPRCommand = Start-Process -PassThru -wait -WindowStyle minimized wpr.exe -WorkingDirectory $resultOutputDir -ArgumentList "-start `"$WPRP`"!WD.Verbose -filemode -instancename AV"
			Test-WPRError $StartWPRCommand.ExitCode
		} 
	} 
	#Downlevel machine with SCEP
	elseif (Test-Path -path "$env:ProgramFiles\Microsoft Security Client\MpCmdRun.exe") {
			CheckAuthenticodeSignature $MpCmdRunCommand
			Start-Process -WindowStyle minimized $MpCmdRunCommand -WorkingDirectory $CurrentMpCmdPath -ArgumentList "-trace -grouping ff -level ff"
	}
}

function Stop-MDAVTrace {
	Write-Host "Stopping and merging Defender Antivirus traces if running"
	if ($WDVerboseTraceV) {
		&$MpCmdRunCommand -CaptureNetworkTrace | Out-File $connectivityCheckFile -Append
		Stop-WinEventDebug Microsoft-Windows-SmartScreen/Debug
	}
	$MpCmdRunProcs = Get-Process | Where-Object { $_.MainWindowTitle -like "*MpCmdRun.ex*" }
	if ($MpCmdRunProcs) {
		foreach ($process in $MpCmdRunProcs) {
			[void][WindowFocus]::SetForeGroundWindow($process.MainWindowHandle) 
			[System.Windows.Forms.SendKeys]::SendWait("~")
		}
	}
	if ($WDPerfTraceA) {
		Check-Command-verified "wpr.exe"
		$StartWPRCommand = Start-Process -PassThru -wait -WindowStyle minimized wpr.exe -WorkingDirectory $resultOutputDir -ArgumentList "-stop merged.etl -instancename AV"
		Test-WPRError $StartWPRCommand.ExitCode
	}
	if (Test-Path -Path  $env:SystemRoot\System32\'Winevt\Logs\Microsoft-Windows-SmartScreen%4Debug.evtx') {
		Copy-Item -path $env:SystemRoot\System32\'Winevt\Logs\Microsoft-Windows-SmartScreen%4Debug.evtx' -Destination $resultOutputDir\EventLogs\SmartScreen.evtx
	}
}

function Get-CrashDump {
	New-Item -ItemType Directory -Path "$resultOutputDir\CrashDumps" -ErrorAction SilentlyContinue | out-Null
	Write-Host "Attempting to collect a memory dump of the sensor"
	if ($ARM) {
		$ProcDumpCommand = Join-Path $ToolsDir "ProcDump64a.exe"
	}
 else {
		$ProcDumpCommand = Join-Path $ToolsDir "procdump.exe" 
	}
	CheckAuthenticodeSignature $ProcDumpCommand
	if ($OSPreviousVersion) {
		$processes = @(Get-Process -Name MsSenseS) + @(Get-Process -Name MonitoringHost)
		if ($processes -eq $null) {
			Write-Host "No running Sensor processes found"
		}
		else {
			foreach ($process in $processes) {
				CheckAuthenticodeSignature $ProcDumpCommand
				& $ProcDumpCommand -accepteula -ma -mk $process.Id "$resultOutputDir\CrashDumps\$($process.name)_$($process.Id).dmp"
			}
		}
	}
	elseif ($buildNumber -ge "15063") {
		Write-Host "The MDEClientAnalyzer does not support capturing a memory dump of a tamper protected process at this time."
		Write-Host "Attempting to capture a memory dump of the DiagTrack service"
		$DiagTrackSvc = (Get-WmiObject Win32_Service -Filter "Name='DiagTrack'")
		$DiagTrackID = $DiagTrackSvc.ProcessId
		if ($DiagTrackID -eq $null) {
			Write-Host "No running processes to capture"
		}
		else {
			$Processes = @(Get-Process -Id $DiagTrackID)
			foreach ($process in $processes) {
				CheckAuthenticodeSignature $ProcDumpCommand
				& $ProcDumpCommand -accepteula -ma -mk $process.Id "$resultOutputDir\CrashDumps\$($process.name)_$($process.Id).dmp"
			}
		}
	}
}

function Start-NetTrace {
	if ($NetTraceI) {
		New-Item -ItemType Directory -Path "$resultOutputDir\NetTraces" -ErrorAction SilentlyContinue | out-Null
		$traceFile = "$resultOutputDir\NetTraces\NetTrace.etl"
		Write-Host "Stopping any running network trace profiles"
		Check-Command-verified "netsh.exe"
		Start-Process -PassThru -WindowStyle minimized netsh.exe -ArgumentList "trace stop" | Out-Null
		Check-Command-verified "netsh.exe"
		Start-Process -PassThru -WindowStyle minimized netsh.exe -ArgumentList "wfp capture stop" | Out-Null
		start-sleep 1
		$NetshProcess = Get-Process | Where-Object { $_.Name -eq "netsh" } -ErrorAction SilentlyContinue
		if ($NetshProcess -ne $null) {
			foreach ($process in $NetshProcess) { stop-Process $process -Force }
		}
		Check-Command-verified "ipconfig.exe"
		Start-Process -PassThru -WindowStyle minimized ipconfig.exe -ArgumentList "/flushdns" | Out-Null
		Check-Command-verified "netsh.exe"
		Start-Process -PassThru -WindowStyle minimized netsh.exe -ArgumentList "interface ip delete arpcache" | Out-Null
		start-sleep 1
		if ($buildNumber -le 7601) {
			Check-Command-verified "netsh.exe"
			Start-Process -WindowStyle hidden netsh.exe -WorkingDirectory "$resultOutputDir\NetTraces" -ArgumentList "trace start overwrite=yes capture=yes scenario=InternetClient report=yes maxSize=500 traceFile=`"$traceFile`" fileMode=circular" | Out-Null
		}
		else {
			Check-Command-verified "netsh.exe"
			Start-Process -WindowStyle hidden netsh.exe -WorkingDirectory "$resultOutputDir\NetTraces" -ArgumentList "trace start overwrite=yes capture=yes scenario=InternetClient_dbg report=yes maxSize=500 traceFile=`"$traceFile`" fileMode=circular"  | Out-Null
		}
		Check-Command-verified "netsh.exe"
		Start-Process -WindowStyle hidden netsh.exe -WorkingDirectory "$resultOutputDir\NetTraces" -ArgumentList "advfirewall set allprofiles logging allowedconnections enable" | Out-Null  # enable firewall logging for allowed traffic
		Check-Command-verified "netsh.exe"
		Start-Process -WindowStyle hidden netsh.exe -WorkingDirectory "$resultOutputDir\NetTraces" -ArgumentList "advfirewall set allprofiles logging droppedconnections enable"  | Out-Null  # enable firewall logging for dropped traffic
		Check-Command-verified "netsh.exe"
		Start-Process -WindowStyle hidden netsh.exe -WorkingDirectory "$resultOutputDir\NetTraces" -ArgumentList "wfp capture start file=wfpdiag.cab keywords=19"  | Out-Null # start capturing  WFP log
		Check-Command-verified "netstat.exe"
		&netstat -anob | Out-File "$resultOutputDir\NetTraces\NetStatOutputAtStart.txt"
		"Netstat output above was taken at: " + (Get-Date) | Out-File "$resultOutputDir\NetTraces\NetStatOutputAtStart.txt" -Append
		if (($OSPreviousVersion) -and (!$MDfWS)) {
			$OMSPath = "$env:ProgramFiles\Microsoft Monitoring Agent\Agent\Tools"
			if (Test-Path -path $OMSPath) {
				Get-Service HealthService | Stop-Service -ErrorAction SilentlyContinue
				&$OMSPath\StopTracing.cmd | Out-Null
				&$OMSPath\StartTracing.cmd VER | Out-Null
				Get-Service HealthService | Start-Service -ErrorAction SilentlyContinue
			}
		}
	}
}

function Stop-NetTrace {
	if ($NetTraceI) {
		Check-Command-verified "netstat.exe"
		&netstat -anob | Out-File "$resultOutputDir\NetTraces\NetStatOutputAtStop.txt"
		"Netstat output above was taken at: " + (Get-Date) | Out-File "$resultOutputDir\NetTraces\NetStatOutputAtStop.txt" -Append
		Check-Command-verified "netsh.exe"
		Start-Process -WindowStyle hidden netsh.exe -WorkingDirectory "$resultOutputDir\NetTraces" -ArgumentList "advfirewall set allprofiles logging allowedconnections disable" | Out-Null  # disable firewall logging for allowed traffic
		Check-Command-verified "netsh.exe"
		Start-Process -WindowStyle hidden netsh.exe -WorkingDirectory "$resultOutputDir\NetTraces" -ArgumentList "advfirewall set allprofiles logging droppedconnections disable" | Out-Null  # disable firewall logging for dropped traffic
		Check-Command-verified "netsh.exe"
		Start-Process -NoNewWindow netsh.exe -WorkingDirectory "$resultOutputDir\NetTraces" -ArgumentList "wfp capture stop"
		Check-Command-verified "netsh.exe"
		Write-Host "Note: Stopping network and wfp traces may take a while..."
		Start-Process -WindowStyle Maximized netsh.exe -WorkingDirectory "$resultOutputDir\NetTraces" -ArgumentList "trace stop"
		Copy-Item $env:SystemRoot\system32\LogFiles\Firewall\pfirewall.log -Destination "$resultOutputDir\NetTraces\" -ErrorAction SilentlyContinue
		if (($MMAPathExists) -and (!$MDfWS)) { 
			&$OMSPath\StopTracing.cmd | Out-Null
			Copy-Item $env:SystemRoot\Logs\OpsMgrTrace\* -Destination "$resultOutputDir\NetTraces\" -ErrorAction SilentlyContinue
		}	
		# Dump HOSTS file content to file
		Copy-Item $env:SystemRoot\System32\Drivers\etc\hosts -Destination "$resultOutputDir\SystemInfoLogs" -ErrorAction SilentlyContinue
		EndTimedoutProcess "netsh" 10
	}
}

# Define C# functions to extract info from Windows Security Center (WSC)
# WSC_SECURITY_PROVIDER as defined in Wscapi.h or http://msdn.microsoft.com/en-us/library/bb432509(v=vs.85).aspx
# And http://msdn.microsoft.com/en-us/library/bb432506(v=vs.85).aspx
$wscDefinition = @"
		[Flags]
        public enum WSC_SECURITY_PROVIDER : int
        {
            WSC_SECURITY_PROVIDER_FIREWALL = 1,				// The aggregation of all firewalls for this computer.
            WSC_SECURITY_PROVIDER_AUTOUPDATE_SETTINGS = 2,	// The automatic update settings for this computer.
            WSC_SECURITY_PROVIDER_ANTIVIRUS = 4,			// The aggregation of all antivirus products for this computer.
            WSC_SECURITY_PROVIDER_ANTISPYWARE = 8,			// The aggregation of all anti-spyware products for this computer.
            WSC_SECURITY_PROVIDER_INTERNET_SETTINGS = 16,	// The settings that restrict the access of web sites in each of the Internet zones for this computer.
            WSC_SECURITY_PROVIDER_USER_ACCOUNT_CONTROL = 32,	// The User Account Control (UAC) settings for this computer.
            WSC_SECURITY_PROVIDER_SERVICE = 64,				// The running state of the WSC service on this computer.
            WSC_SECURITY_PROVIDER_NONE = 0,					// None of the items that WSC monitors.
			
			// All of the items that the WSC monitors.
            WSC_SECURITY_PROVIDER_ALL = WSC_SECURITY_PROVIDER_FIREWALL | WSC_SECURITY_PROVIDER_AUTOUPDATE_SETTINGS | WSC_SECURITY_PROVIDER_ANTIVIRUS |
            WSC_SECURITY_PROVIDER_ANTISPYWARE | WSC_SECURITY_PROVIDER_INTERNET_SETTINGS | WSC_SECURITY_PROVIDER_USER_ACCOUNT_CONTROL |
            WSC_SECURITY_PROVIDER_SERVICE | WSC_SECURITY_PROVIDER_NONE
        }

        [Flags]
        public enum WSC_SECURITY_PROVIDER_HEALTH : int
        {
            WSC_SECURITY_PROVIDER_HEALTH_GOOD, 			// The status of the security provider category is good and does not need user attention.
            WSC_SECURITY_PROVIDER_HEALTH_NOTMONITORED,	// The status of the security provider category is not monitored by WSC. 
            WSC_SECURITY_PROVIDER_HEALTH_POOR, 			// The status of the security provider category is poor and the computer may be at risk.
            WSC_SECURITY_PROVIDER_HEALTH_SNOOZE, 		// The security provider category is in snooze state. Snooze indicates that WSC is not actively protecting the computer.
            WSC_SECURITY_PROVIDER_HEALTH_UNKNOWN
        }

		
        [DllImport("wscapi.dll")]
        private static extern int WscGetSecurityProviderHealth(int inValue, ref int outValue);

		// code to call interop function and return the relevant result
        public static WSC_SECURITY_PROVIDER_HEALTH GetSecurityProviderHealth(WSC_SECURITY_PROVIDER inputValue)
        {
            int inValue = (int)inputValue;
            int outValue = -1;

            int result = WscGetSecurityProviderHealth(inValue, ref outValue);

            foreach (WSC_SECURITY_PROVIDER_HEALTH wsph in Enum.GetValues(typeof(WSC_SECURITY_PROVIDER_HEALTH)))
                if ((int)wsph == outValue) return wsph;

            return WSC_SECURITY_PROVIDER_HEALTH.WSC_SECURITY_PROVIDER_HEALTH_UNKNOWN;
        }
"@

# Add-type to use SetForegroundWindow api https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setforegroundwindow
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") 
Add-Type @"
  using System;
  using System.Runtime.InteropServices;
  public class WindowFocus {
     [DllImport("user32.dll")]
     [return: MarshalAs(UnmanagedType.Bool)]
     public static extern bool SetForegroundWindow(IntPtr hWnd);
  }
"@

function Get-Log {
	New-Item -ItemType Directory -Path "$resultOutputDir\DefenderAV" -ErrorAction SilentlyContinue | out-Null
	StartGet-MSInfo -NFO $true -TXT $false -OutputLocation "$resultOutputDir\SystemInfoLogs"
	Check-Command-verified "gpresult.exe"
	&gpresult /SCOPE COMPUTER /H "$resultOutputDir\SystemInfoLogs\GP.html"
	if ($MpCmdRunCommand) {
		Write-Host "Running MpCmdRun -GetFiles..."
		CheckAuthenticodeSignature $MpCmdRunCommand
		&$MpCmdRunCommand -getfiles | Out-File "$resultOutputDir\DefenderAV\GetFilesLog.txt" -Append
		Copy-Item -Path "$MpCmdResultPath\MpSupportFiles.cab" -Destination "$resultOutputDir\DefenderAV" -verbose -ErrorVariable GetFilesErr | Out-File "$resultOutputDir\DefenderAV\GetFilesLog.txt" -Append
		$GetFilesErr | Out-File "$resultOutputDir\DefenderAV\GetFilesLog.txt" -Append
		Copy-Item -path "C:\Users\Public\Downloads\Capture.npcap" -Destination "$resultOutputDir\DefenderAV" -ErrorAction SilentlyContinue -verbose -ErrorVariable CopyNpCap | Out-File "$resultOutputDir\DefenderAV\GetFilesLog.txt" -Append
		$CopyNpCap | Out-File "$resultOutputDir\DefenderAV\GetFilesLog.txt" -Append
		Copy-Item -path "C:\Users\Public\Downloads\Capture.npcap.injections" -Destination "$resultOutputDir\DefenderAV" -ErrorAction SilentlyContinue -verbose -ErrorVariable CopyNpCapInjections | Out-File "$resultOutputDir\DefenderAV\GetFilesLog.txt" -Append
		$CopyNpCapInjections | Out-File "$resultOutputDir\DefenderAV\GetFilesLog.txt" -Append		# Dump Defender related polices
		Get-ChildItem "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -recurse | Out-File "$resultOutputDir\DefenderAV\Policy-DefenderAV.txt"
		Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Configurable\" -recurse | Out-File "$resultOutputDir\DefenderAV\Policy-Firewall.txt"
		Get-ChildItem "HKU:\S-1-5-18\SOFTWARE\Microsoft\Windows Defender" -recurse -ErrorAction SilentlyContinue | Out-File "$resultOutputDir\DefenderAV\Policy-SystemService.txt"
		Get-ChildItem "HKU:\S-1-5-20\SOFTWARE\Microsoft\Windows Defender" -recurse -ErrorAction SilentlyContinue | Out-File "$resultOutputDir\DefenderAV\Policy-NetworkService.txt"
	}
	Check-Command-verified "fltmc.exe"
	&fltmc instances -v "$env:SystemDrive" > $resultOutputDir\SystemInfoLogs\filters.txt
	if ($OSProductName.tolower() -notlike ("*server*")) {
		Write-output "`r`n##################### Windows Security Center checks ######################" | Out-File $connectivityCheckFile -Append
		$wscType = Add-Type -memberDefinition $wscDefinition -name "wscType" -UsingNamespace "System.Reflection", "System.Diagnostics" -PassThru
 
		"            Firewall: " + $wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_FIREWALL) | Out-File $connectivityCheckFile -Append
		"         Auto-Update: " + $wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_AUTOUPDATE_SETTINGS) | Out-File $connectivityCheckFile -Append
		"          Anti-Virus: " + $wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_ANTIVIRUS) | Out-File $connectivityCheckFile -Append
		"        Anti-Spyware: " + $wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_ANTISPYWARE) | Out-File $connectivityCheckFile -Append
		"   Internet Settings: " + $wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_INTERNET_SETTINGS) | Out-File $connectivityCheckFile -Append
		"User Account Control: " + $wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_USER_ACCOUNT_CONTROL) | Out-File $connectivityCheckFile -Append
		"         WSC Service: " + $wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_SERVICE) | Out-File $connectivityCheckFile -Append

		if ($wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_FIREWALL) -eq $wscType[2]::WSC_SECURITY_PROVIDER_HEALTH_POOR) {
			Write-output "Windows Defender firewall settings not optimal" | Out-File $connectivityCheckFile -Append
		}
		if ($wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_USER_ACCOUNT_CONTROL) -eq $wscType[2]::WSC_SECURITY_PROVIDER_HEALTH_POOR) {
			Write-output "User Account Controller (UAC) is switched off" | Out-File $connectivityCheckFile -Append
		}
		if ($wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_ANTIVIRUS) -eq $wscType[2]::WSC_SECURITY_PROVIDER_HEALTH_GOOD) {
			Write-output "Windows Defender anti-virus is running and up-to-date" | Out-File $connectivityCheckFile -Append
		}
	}
}

function StartTimer {
	$TraceStartTime = "{0:dd/MM/yyyy h:mm:ss tt zzz}" -f (get-date)
	Write-Report -section "general" -subsection "traceStartTime" -displayname "Trace StartTime: " -value $TraceStartTime
	$timeout = New-TimeSpan -Minutes $MinutesToRun
	$sw = [diagnostics.stopwatch]::StartNew()
	Create-OnDemandStartEvent
	if ($RemoteRun) {
		Write-Warning "Trace started... Note that you can stop this non-interactive mode by running 'MDEClientAnalyzer.cmd' from another window or session"
		Wait-OnDemandStop
	} else {
		while ($sw.elapsed -lt $timeout) {
			Start-Sleep -Seconds 1
			$rem = $timeout.TotalSeconds - $sw.elapsed.TotalSeconds
			Write-Progress -Activity "Collecting traces, run your scenario now and press 'q' to stop data collection at any time" -Status "Progress:"  -SecondsRemaining $rem -PercentComplete (($sw.elapsed.Seconds / $timeout.TotalSeconds) * 100)
			if ([console]::KeyAvailable) {
				$key = [System.Console]::ReadKey() 
				if ( $key.key -eq 'q') {
					Write-Warning  "The trace collection action was ended by user exit command"
					break 
				}
			}
		}
	}
	$TraceStopTime = "{0:dd/MM/yyyy h:mm:ss tt zzz}" -f (get-date)
	Write-Report -section "general" -subsection "traceStopTime" -displayname "Trace StopTime: " -value $TraceStopTime 
}

function Get-MinutesValue {
	if ($RemoteRun) {
		"`r`nLog Collection was started from a remote device." | Out-File $connectivityCheckFile -Append
		return $MinutesToRun
	} 
	else {
		do {
			try {
				[int]$MinutesToRun = (Read-Host "Enter the number of minutes to collect traces")
				return $MinutesToRun
			}
			catch {
				Write-Warning  ($_.Exception.Message).split(':')[1]
				$MinutesToRun = $false
			}
		} while ($MinutesToRun -eq $false)
	}
}

function Test-WptState($command) {
	if (!$command) {
		$CheckCommand = (Get-Command "wpr.exe" -ErrorAction SilentlyContinue)
	} else {
		$CheckCommand = (Get-Command $command -ErrorAction SilentlyContinue)
	}
	# This line will reload the path so that a recent installation of wpr will take effect immediately:
	$env:path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
	$SenseWprp7 = Join-Path $ToolsDir "SenseW7.wprp"
	$SenseWprp10 = Join-Path $ToolsDir "SenseW10.wprp"
	$SenseWprp = Join-Path $ToolsDir "Sense.wprp"
	$DlZipFile = Join-Path $ToolsDir "WPT.cab"
	if (($CheckCommand -eq $null) -and ($InteractiveAdmin)) {
		Write-Warning "Performance Toolkit is not installed on this device. It is required for full traces to be collected."
		Write-host -ForegroundColor Green "Please wait while we download WPT installer files (~50Mb) to MDEClientAnalyzer directory. Refer to https://aka.ms/adk for more information about the 'Windows ADK'."
		$WPTURL = "https://aka.ms/MDATPWPT"
		Import-Module BitsTransfer
		$BitsResult = Start-BitsTransfer -Source $WPTURL -Destination "$DlZipFile" -TransferType Download -Asynchronous
		$DownloadComplete = $false
		if (!(Test-Path -path $DlZipFile)) {
			while ($DownloadComplete -ne $true) {
				start-Sleep 1
				$jobstate = $BitsResult.JobState;
				$percentComplete = ($BitsResult.BytesTransferred / $BitsResult.BytesTotal) * 100
				Write-Progress -Activity ('Downloading' + $result.FilesTotal + ' files') -Status "Progress:" -PercentComplete $percentComplete 
				if ($jobstate.ToString() -eq 'Transferred') {
					$DownloadComplete = $true
					Write-Progress -Activity ('Downloading' + $result.FilesTotal + ' files') -Completed close 
				}
				if ($jobstate.ToString() -eq 'TransientError') {
					$DownloadComplete = $true
					Write-host "Unable to download ADK installation package."
				}
			}
			$BitsResult | complete-BitsTransfer
		}
		if (Test-Path -path "$DlZipFile") {
			CheckHashFile "$DlZipFile" "6FE5F8CA7F864560B9715E0C18AA0D839416EDB0B68B4A314FC96DFAFA99733E"
			Check-Command-verified "expand.exe"
			#Expand-Archive CMDlet or System.IO.Compression.ZipFile does not work with some older PowerShell/OS combinations so using the below for backwards compatbility 
			&expand.exe "$DlZipFile" "`"$($ToolsDir.TrimEnd('\'))`"" -F:*
			Write-host -ForegroundColor Green "Download complete. Starting installer..."
			start-Sleep 1
			Write-Host -BackgroundColor Red -ForegroundColor Yellow "Please click through the installer steps to deploy the Microsoft Windows Performance Toolkit (WPT) before proceeding"
			if ($buildNumber -eq 7601) {
				$AdkSetupPath = Join-Path $ToolsDir "8.0\adksetup.exe"
				CheckAuthenticodeSignature $AdkSetupPath
				Start-Process -wait -WindowStyle minimized "$AdkSetupPath" -ArgumentList "/ceip off /features OptionId.WindowsPerformanceToolkit"
				Read-Host "Press ENTER if intallation is complete and you are ready to resume..."	
			}
			elseif ($buildNumber -gt 7601) {
				$AdkSetupPath = Join-Path $ToolsDir "adksetup.exe"
				CheckAuthenticodeSignature $AdkSetupPath
				Start-Process -wait -WindowStyle minimized "$AdkSetupPath" -ArgumentList "/ceip off /features OptionId.WindowsPerformanceToolkit"
				Read-Host "Press ENTER if intallation is complete and you are ready to resume..."
			}
		}
		else {
			Write-host "Please download and install manually from https://aka.ms/adk" 
		}
		# If install is successful we need to refresh environemnt variable and check if command got installed
		$env:path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
		$CheckCommand = (Get-Command $command -ErrorAction SilentlyContinue)
		if ($CheckCommand -eq $null) {
			Write-Host -BackgroundColor Red -ForegroundColor Yellow "WPT was not installed. Only partial data will be collected"
			return
		}
		elseif ($buildNumber -eq 7601) {
			Write-Warning "Note: Windows7/2008R2 devices also require running 'wpr.exe -disablepagingexecutive on' and rebooting"
			Write-Warning "To disable, run 'wpr.exe -disablepagingexecutive off' once data collection is complete"
			Read-Host "Press ENTER to allow MDEClientAnalyzer to turn on 'disablepagingexecutive' and restart your device automatically"
			$StartWPRCommand = Start-Process -PassThru -wait -WindowStyle minimized wpr.exe -ArgumentList "-disablepagingexecutive on"
			Test-WPRError $StartWPRCommand.ExitCode
			Restart-Computer -ComputerName .
		}
	}
 else {
		Write-Host "Stopping any running WPR trace profiles"
		Check-Command-verified "wpr.exe"
		$StartWPRCommand = Start-Process -PassThru -wait -WindowStyle minimized wpr.exe  -ArgumentList "-cancel"
		Test-WPRError $StartWPRCommand.ExitCode
	}
	if ($buildNumber -le 9600) {
		Copy-Item -path $SenseWprp7 -Destination $senseWprp -Force	
	}
	else {
		Copy-Item -path $SenseWprp10 -Destination $senseWprp -Force
	}		
	return $WptState = "Ready"
}

function Start-Wpr {
	Check-Command-verified "wpr.exe"
	if ($wprpTraceH -and $WptState -eq "Ready") {
		Check-Command-verified "wpr.exe"
		$StartWPRCommand = Start-Process -PassThru -wait -WindowStyle minimized wpr.exe -ArgumentList "-start GeneralProfile -start CPU -start FileIO -start DiskIO -start `"$ToolsDir\Sense.wprp`" -filemode -instancename Sense"
		Test-WPRError $StartWPRCommand.ExitCode
	}
	elseif ($WptState -eq "Ready") {
		Check-Command-verified "wpr.exe"
		$StartWPRCommand = Start-Process -PassThru -wait -WindowStyle minimized wpr.exe -ArgumentList "-start `"$ToolsDir\Sense.wprp`" -filemode -instancename Sense"
		Test-WPRError $StartWPRCommand.ExitCode
	}
}

function Stop-Wpr {
	if ($WptState -eq "Ready") {
		Check-Command-verified "wpr.exe"
		$StartWPRCommand = Start-Process -PassThru -wait -WindowStyle minimized wpr.exe -ArgumentList "-stop `"$WprpTraceFile`" -instancename Sense"
		Test-WPRError $StartWPRCommand.ExitCode
	}
}

function Copy-RecentItem($ParentFolder, $DestFolderName) {
	$ParentFolder = (Get-ChildItem -Path $ParentFolder)
	$ParentFolder = ($ParentFolder | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-2) } -ErrorAction SilentlyContinue)
	if ($ParentFolder -ne $null) {
		foreach ($subfolder in $ParentFolder) {
			Copy-Item -Recurse -Path $subfolder.FullName -Destination $resultOutputDir\$DestFolderName\$subfolder -ErrorAction SilentlyContinue
		}
	}
}

function Start-WinEventDebug($DebugLogName) {
	$log = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $DebugLogName
	if ($log.IsEnabled -ne $true) {
		$log.IsEnabled = $true
		$log.SaveChanges()
	}
}

function Stop-WinEventDebug($DebugLogName) {
	$log = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $DebugLogName
	$log.IsEnabled = $false
	$log.SaveChanges()
	$DebugLogPath = [System.Environment]::ExpandEnvironmentVariables($log.LogFilePath)
	Copy-Item -path "$DebugLogPath" -Destination "$resultOutputDir\EventLogs\"
}

function SetLocalDumps() {
	# If already implementing LocalDumps as per https://docs.microsoft.com/en-us/windows/win32/wer/collecting-user-mode-dumps, then backup the current config
	if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps") {
		Check-Command-verified "reg.exe"
		&Reg export "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" "$ToolsDir\WerRegBackup.reg" /y 2>&1 | Out-Null
	}  
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" -Recurse -ErrorAction SilentlyContinue | out-Null
	New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "LocalDumps" -ErrorAction SilentlyContinue | out-Null
	New-Item -ItemType Directory -Path "$resultOutputDir\CrashDumps" -ErrorAction SilentlyContinue | out-Null
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" -Name "DumpFolder" -Value "$resultOutputDir\CrashDumps" -PropertyType "ExpandString" -ErrorAction SilentlyContinue | out-Null
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" -Name "DumpCount" -Value 5 -PropertyType DWord -ErrorAction SilentlyContinue | out-Null
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" -Name "DumpType" -Value 2 -PropertyType DWord -ErrorAction SilentlyContinue | out-Null
}

function RestoreLocalDumps() {
	if (Test-Path "$ToolsDir\WerRegBackup.reg") {
		Check-Command-verified "reg.exe"
		&reg.exe import "$ToolsDir\WerRegBackup.reg" 2>&1 | Out-Null
	}
 else {
		Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" -ErrorAction SilentlyContinue | out-Null
	}
}

# function to download a given cab file and expand it
function Get-WebFile($webfile) {
	$DlZipFile = Join-Path $ToolsDir "webfile.cab"
	Write-host -ForegroundColor Green "Please wait while we download additional required files to MDEClientAnalyzer from: " $webfile
	Import-Module BitsTransfer
	Start-BitsTransfer -source $webfile -Destination "$DlZipFile" -Description "Downloading additional files" -RetryTimeout 60 -RetryInterval 60 -ErrorAction SilentlyContinue | Out-Null
}

function Start-AppCompatTrace() {
	if ($AppCompatC) {
		if ($InteractiveAdmin) {
		# We can't use bits to fetch symchk if user is not interactive
			if (!$OSPreviousVersion) {
				$SymChkCommand = Join-Path $ToolsDir "\x86\symchk.exe"
				$DlZipFile = Join-Path $ToolsDir "webfile.cab"
				if (!(test-path $SymChkCommand)) {
					Get-WebFile "https://aka.ms/MDATPSYMCHK"
					if (Test-Path -path "$DlZipFile" -ErrorAction SilentlyContinue) {
						Check-Command-verified "expand.exe"
						CheckHashFile "$DlZipFile" "DE3E5338E4EBEBA64250E61E91CAFC86A70EA999C2E2D8E0A769862B2B642168"
						#Expand-Archive CMDlet or System.IO.Compression.ZipFile does not work with some older PowerShell/OS combinations so using the below for backwards compatbility 
						&expand.exe "$DlZipFile" "`"$($ToolsDir.TrimEnd('\'))`"" -F:*
					}
				}
				if (test-path $SymChkCommand) {
					CheckAuthenticodeSignature $SymChkCommand
					&$SymChkCommand /q /r /s "." "$env:ProgramFiles\Windows Defender Advanced Threat Protection" /om "$resultOutputDir\SystemInfoLogs\symbolsManifest.txt"
				}
			}
		}
		if ($ARM) {
			$ProcmonCommand = Join-Path $ToolsDir "Procmon64a.exe"
		}
		else {
			$ProcmonCommand = Join-Path $ToolsDir "Procmon.exe"
		}
		CheckAuthenticodeSignature $ProcmonCommand
		&$ProcmonCommand -AcceptEula -Terminate
		Remove-Item $ToolsDir\*.pml -Force -ErrorAction SilentlyContinue
		CheckAuthenticodeSignature $ProcmonCommand
		&$ProcmonCommand -AcceptEula -BackingFile "$resultOutputDir\procmonlog.pml" -NoFilter -Quiet -Minimized 
		Start-WinEventDebug Microsoft-Windows-WMI-Activity/Debug
		SetLocalDumps
	}
}

function Stop-AppCompatTrace() {
	if ($AppCompatC) {
		if ($ARM) {
			$ProcmonCommand = Join-Path $ToolsDir "Procmon64a.exe"
		}
		else {
			$ProcmonCommand = Join-Path $ToolsDir "Procmon.exe"
		}		
		CheckAuthenticodeSignature $ProcmonCommand
		Write-Host "Stopping procmon trace..."
		&$ProcmonCommand -AcceptEula -Terminate
		if (Test-Path -Path  $env:SystemRoot\System32\'Winevt\Logs\Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider%4Admin.evtx') {
			Copy-Item -path $env:SystemRoot\System32\'Winevt\Logs\Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider%4Admin.evtx' -Destination $resultOutputDir\EventLogs\MdmAdmin.evtx
			Copy-Item -path $env:SystemRoot\System32\'Winevt\Logs\Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider%4Operational.evtx' -Destination $resultOutputDir\EventLogs\MdmOperational.evtx -ErrorAction SilentlyContinue
		}
		Stop-WinEventDebug Microsoft-Windows-WMI-Activity/Debug
		Copy-Item -path $env:SystemRoot\System32\'Winevt\Logs\Microsoft-Windows-WMI-Activity%4Operational.evtx' -Destination $resultOutputDir\EventLogs\WMIActivityOperational.evtx
		Copy-Item -path $env:SystemRoot\System32\'Winevt\Logs\System.evtx' -Destination $resultOutputDir\EventLogs\System.evtx
		Copy-Item -path $env:SystemRoot\System32\'Winevt\Logs\Application.evtx' -Destination $resultOutputDir\EventLogs\Application.evtx
		Copy-Item -path $env:SystemRoot\System32\'Winevt\Logs\Microsoft-Windows-PushNotification-Platform%4Operational.evtx' -Destination $resultOutputDir\EventLogs\PushNotification-Platform-Operational.evtx

		$DestFolderName = "WER"
		Copy-RecentItem $env:ProgramData\Microsoft\Windows\WER\ReportArchive $DestFolderName
		Copy-RecentItem $env:ProgramData\Microsoft\Windows\WER\ReportQueue $DestFolderName
		RestoreLocalDumps
	}
}		

function Stop-PerformanceCounter {
	param (
		$DataCollectorSet,
		$DataCollectorName
	)
	try {
		$DataCollectorSet.Query($DataCollectorName, $null)
		if ($DataCollectorSet.Status -ne 0) {
			$DataCollectorSet.stop($false)
			Start-Sleep 10
		}
           
		$DataCollectorSet.Delete()
	}
	catch [Exception] {
		$_.Exception.Message
	}
}

function Get-PerformanceCounter {
	param (
		[Alias("r")][switch]$RunCounter
	)

	$filePathToXml = "$ToolsDir\PerfCounter.xml"
	if ($RunCounter) {
		if (($buildNumber -eq 9600) -or ($buildNumber -eq 7601)) {
			Copy-Item  -path "$ToolsDir\PerfCounterW7.xml" -Destination  "$ToolsDir\PerfCounter.xml" -Force
		}
		else {
			Copy-Item  -path "$ToolsDir\PerfCounterW10.xml"  -Destination  "$ToolsDir\PerfCounter.xml" -Force
		}   
		$xmlContent = New-Object XML
		$xmlContent.Load($filePathToXml)
		$xmlContent.SelectNodes("//OutputLocation") | ForEach-Object { $_."#text" = $_."#text".Replace('c:\', $ToolsDir) }
		$xmlContent.SelectNodes("//RootPath") | ForEach-Object { $_."#text" = $_."#text".Replace('c:\', $ToolsDir) }
		$xmlContent.Save($filePathToXml)
	}

	$DataCollectorName = "MDE-Perf-Counter"
	$DataCollectorSet = New-Object -COM Pla.DataCollectorSet
	[string]$xml = Get-Content $filePathToXml
	$DataCollectorSet.SetXml($xml)
	Write-Host "Stopping any running perfmon trace profiles"
	Stop-PerformanceCounter -DataCollectorSet  $DataCollectorSet -DataCollectorName $DataCollectorName >$null
	if ($RunCounter) {
		$DataCollectorSet.Commit("$DataCollectorName" , $null , 0x0003) | Out-Null
		$DataCollectorSet.Start($false)
	}
}

function Start-PerformanceTrace() {
	if ($wprpTraceL) {
		Get-PerformanceCounter -r
	}
}

function Stop-PerformanceTrace() {
	if ($wprpTraceL) {
		Get-PerformanceCounter		
	}
	$Perfmonlogs = Get-Item $ToolsDir\*.blg
	if (($Perfmonlogs) -ne $null) {
		Move-Item -Path $Perfmonlogs -Destination $resultOutputDir
	} 
}

function SetUrlList {
	param (
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]$OSPreviousVersion
	)
	$Urls = @{}
	
	$RegionsObj = (Get-Content $RegionsJson -raw) | ConvertFrom-Json
	if ((Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection" -Value OnboardedInfo) -or ($ASM)) {
		Clear-Content -Path $EndpointList	

		if ($asm) {
			# Datacenter not relevant at this time
			$Region = "ASM"
		}
		Else {
			$OnboardedInfo = (((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\").OnboardedInfo | ConvertFrom-Json).body | ConvertFrom-Json)
			$Region = $OnboardedInfo.vortexGeoLocation
			$Datacenter = $OnboardedInfo.Datacenter
		}
		$regionURLs = ($RegionsObj | Where-Object { ($_.Region -eq $Region) -and ($Datacenter -like "$($_.datacenterprefix)*") })
		if ($regionURLs -ne $null) {
			Add-Content $EndpointList -value $regionURLs.CnCURLs
			Add-Content $EndpointList -value $regionURLs.CyberDataURLs
			Add-Content $EndpointList -value $regionURLs.AutoIRBlobs
			Add-Content $EndpointList -value $regionURLs.SampleUploadBlobs
			Add-Content $EndpointList -value $regionURLs.MdeConfigMgr

			$Urls['CnCURLs'] = $regionURLs.CnCURLs
			$Urls['CyberDataURLs'] = $regionURLs.CyberDataURLs
			$Urls['AutoIRBlobs'] = $regionURLs.AutoIRBlobs
			$Urls['SampleUploadBlobs'] = $regionURLs.SampleUploadBlobs
			$Urls['MdeConfigMgr'] = $regionURLs.MdeConfigMgr
		}
		
		if (($Region) -notmatch 'FFL') {
			$regionAllURLs = ($RegionsObj | Where-Object { $_.Region -eq "ALL" });
			Add-Content $EndpointList -value $regionAllURLs.CTLDL
			Add-Content $EndpointList -value $regionAllURLs.Settings
			Add-Content $EndpointList -value $regionAllURLs.Events
		}
		$AllRegionsURLs['Region'] = $Region
		$AllRegionsURLs['Urls'] = $Urls
	} 
	elseif ($OSPreviousVersion) {
		Clear-Content -Path $EndpointList
		$Regions = ('US', 'UK', 'EU')
		foreach ($Region in $Regions) {
			Add-Content $EndpointList -value ($RegionsObj | Where-Object { $_.Region -eq $Region }).CnCURLs
			$Urls['CnCURLs'] = ($RegionsObj | Where-Object { $_.Region -eq $Region }).CnCURLs
			$AllRegionsURLs['Region'] = $Region
			$AllRegionsURLs['Urls'] = $Urls
		}
	}
}

function ValidateURLs {
	# Add warning to output if any EDR Cloud checks failed
	# Based on https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/configure-proxy-internet#verify-client-connectivity-to-microsoft-defender-atp-service-urls
	# "If at least one of the connectivity options returns a (200) status, then the Microsoft Defender for Endpoint client can communicate with the tested URL properly using this connectivity method."
	Write-output "`r`n#################### Defender for Endpoint cloud service check #####################" | Out-File $connectivityCheckFile -Append
	$Streamer = New-Object System.IO.StreamReader( $connectivityCheckFile)
	$SuccessCounter = -1

	$AllUrlsErrors = New-Object System.Collections.Generic.List[System.Object]
	while (($Line = $Streamer.ReadLine()) -ne $null) {
		If ($Line -like "*Testing URL :*") {
			$UrlToCheck = $Line.substring(14)
			$SuccessCounter = 0       
			For ($i = 0; $i -le 5; $i++) {
				$Line = $Streamer.ReadLine()
				If (($Line -like "*(200)*") -or ($Line -like "*(400)*") -or ($Line -like "*(404)*")) {
					$SuccessCounter += 1
				}
			}
			If ($SuccessCounter -eq 0) {
				 if (-not [String]::IsNullOrWhiteSpace($currentSection) -and $null -ne $UrlToCheck) {
						Add-Member -InputObject $AllUrlsErrors -MemberType NoteProperty -Name $currentSection -Value $UrlToCheck -ErrorAction SilentlyContinue
				   }
				[void]$AllUrlsErrors.Add($UrlToCheck)
			}
		}
	}
	$Streamer.Dispose()
	if ($SuccessCounter -eq -1) {
		WriteReport 131001 @() @()
	}
	else {
		#Urls connectivity checks by region
		if ($AllRegionsURLs.Region -eq 'ASM') {
			CheckCnCURLs $AllRegionsURLs $AllUrlsErrors
		}
		If ($AllRegionsURLs.Region -eq 'US' -or $AllRegionsURLs.Region -eq 'UK' -or $AllRegionsURLs.Region -eq 'EU') {
			CheckCnCURLs $AllRegionsURLs $AllUrlsErrors
			CheckCyberURLs $AllRegionsURLs $AllUrlsErrors
			CheckAutoIR $AllRegionsURLs $AllUrlsErrors
			CheckSampleUpload $AllRegionsURLs $AllUrlsErrors
			CheckMdeConfigMgr $AllRegionsURLs $AllUrlsErrors
		}
		If ($AllRegionsURLs.Region -like ("FFL*")) {
			CheckCnCURLs $AllRegionsURLs $AllUrlsErrors
			CheckCyberURLs $AllRegionsURLs $AllUrlsErrors
			CheckAutoIR $AllRegionsURLs $AllUrlsErrors
			CheckMdeConfigMgr $AllRegionsURLs $AllUrlsErrors
		}
	}
}

function CountErrors($AllUrlsErrors, $AllConnectivity, $ConnectivityCheck) {
	$CheckURLs = $AllConnectivity.$ConnectivityCheck
	$CountErrors = 0
	$Errors = New-Object System.Collections.Generic.List[System.Object]
	If ($AllUrlsErrors.Count -gt 0 -and $CheckURLs.Count -gt 0) {
		foreach ($url in $CheckURLs) {
			If ($AllUrlsErrors.Contains($url)) {
				$CountErrors += 1
				[void]$Errors.Add($url)
			}
		}
	}
	$ParsedErrors = @()
	foreach ($Error in $Errors) {
		$ParsedErrors += "<a href='" + $Error + "'>" + $Error + "</a>"
	}
	return $CountErrors, $ParsedErrors
}

function CheckCnCURLs($AllRegionsURLs, $AllUrlsErrors) {
	$AllConnectivity = $AllRegionsURLs.Urls
	$CncErrorCnt, $Errors = CountErrors $AllUrlsErrors $AllConnectivity 'CnCURLs'

	If ($CncErrorCnt -gt 1) {
		WriteReport 132021 @(, @($Errors)) @()
	}
	elseif ($CncErrorCnt -eq 0) {
		WriteReport 130017 @() @()
	}
	else {
		WriteReport 131013 @(, @($Errors)) @()
	}
}

function CheckCyberURLs($AllRegionsURLs, $AllUrlsErrors) {
	$AllConnectivity = $AllRegionsURLs.Urls
	$CyberErrorCnt, $Errors = CountErrors $AllUrlsErrors $AllConnectivity 'CyberDataURLs'

	If ($CyberErrorCnt -gt 1) {
		WriteReport 132022 @(, @($Errors)) @()
	}
	elseif ($CyberErrorCnt -eq 0) {
		WriteReport 130018 @() @()
	}
	else {
		WriteReport 131014 @(, @($Errors)) @()
	}
}

function CheckAutoIR($AllRegionsURLs, $AllUrlsErrors) {
	$AllConnectivity = $AllRegionsURLs.Urls
	$AutoIRCnt, $Errors = CountErrors $AllUrlsErrors $AllConnectivity 'AutoIRBlobs'

	If ($AutoIRCnt -gt 1) {
		WriteReport 132023 @(, @($Errors)) @()
	}
	elseif ($AutoIRCnt -eq 0) {
		WriteReport 130019  @() @()
	}
	else {
		WriteReport 131015 @(, @($Errors)) @()
	}
}

function CheckSampleUpload($AllRegionsURLs, $AllUrlsErrors) {
	$AllConnectivity = $AllRegionsURLs.Urls
	$SampleUploadCnt, $Errors = CountErrors $AllUrlsErrors $AllConnectivity 'SampleUploadBlobs'

	If ($SampleUploadCnt -gt 1) {
		WriteReport 132024 @(, @($Errors)) @()
	}
	elseif ($SampleUploadCnt -eq 0) {
		WriteReport 130020 @() @()
	}
	else {
		WriteReport 131016 @(, @($Errors)) @()
	}
}

function CheckMdeConfigMgr($AllRegionsURLs, $AllUrlsErrors) {
	$AllConnectivity = $AllRegionsURLs.Urls
	$MdeConfigMgrCnt, $Errors = CountErrors $AllUrlsErrors $AllConnectivity 'MdeConfigMgr'

	If ($MdeConfigMgrCnt -gt 1) {
		WriteReport 132025 @(, @($Errors)) @()
	}
	elseif ($MdeConfigMgrCnt -eq 0) {
		WriteReport 130021 @() @()
	}
	else {
		WriteReport 131017 @(, @($Errors)) @()
	}
}

function Enter-CheckURL() {
	$PSExecCommand = Join-Path $ToolsDir "PsExec.exe"
	$MDEClientAnalyzerCommand = Join-Path $ToolsDir "MDEClientAnalyzer.exe"
	$URLCheckLog = Join-Path $ToolsDir "URLCheckLog.txt"
	$psexeclog = Join-Path $ToolsDir "psexeclog.txt"
	if (test-Path -path $PSExecCommand) {
		CheckAuthenticodeSignature $PSExecCommand
		CheckAuthenticodeSignature $MDEClientAnalyzerCommand
		Start-Process `
			-WorkingDirectory $ToolsDir `
			-FilePath $PSExecCommand `
			-WindowStyle Hidden `
			-RedirectStandardOutput $URLCheckLog `
			-RedirectStandardError $psexeclog `
			-ArgumentList "$ARMcommand -accepteula -nobanner -s -w `"$ToolsDir`" `"$MDEClientAnalyzerCommand`""
	}
}

function CheckConnectivity {
 param (
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]$OSPreviousVersion,
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]$connectivityCheckFile,
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]$connectivityCheckUserFile
	)

	[version]$mindotNet = "4.0.30319"
	$PSExecCommand = Join-Path $ToolsDir "PsExec.exe"
	if (test-Path -path $PSExecCommand) {
		CheckAuthenticodeSignature $PSExecCommand
	}
	$MDEClientAnalyzerCommand = Join-Path $ToolsDir "MDEClientAnalyzer.exe"
	CheckAuthenticodeSignature $MDEClientAnalyzerCommand
	$MDEClientAnalyzerPreviousVersionCommand = Join-Path $ToolsDir "MDEClientAnalyzerPreviousVersion.exe"
	$URLCheckLog = Join-Path $ToolsDir "URLCheckLog.txt"
	$psexeclog = Join-Path $ToolsDir "psexeclog.txt"

	SetUrlList -OSPreviousVersion $OSPreviousVersion

	if ((Get-RegistryValue -Path  "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Client" -Value Version)) {
		[version]$dotNet = Get-RegistryValue -Path  "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Client" -Value Version
	}
 else {
		[version]$dotNet = "0.0.0000"
	}
	
	if ((!$OSPreviousVersion) -or ($MDfWS)) {		        
		"`r`nImportant notes:" | Out-File $connectivityCheckFile -Append
		"1. If at least one of the connectivity options returns status (200), then Defender for Endpoint sensor can properly communicate with the tested URL using this connectivity method." | Out-File $connectivityCheckFile -Append
		"2. For *.blob.core.*.net URLs, return status (400) is expected. However, the current connectivity test on Azure blob URLs cannot detect SSL inspection scenarios as it is performed without certificate pinning." | Out-File $connectivityCheckFile -Append
		
		
		
		"For more information on certificate pinning, please refer to: https://docs.microsoft.com/en-us/windows/security/identity-protection/enterprise-certificate-pinning" | Out-File $connectivityCheckFile -Append
		# check if running with system context (i.e. script was most likely run remotely via "psexec.exe -s \\device command" or Live Response)
		if ($system) {
			"`r`nConnectivity output, running as System:" | Out-File $connectivityCheckFile -Append
			Set-Location -Path $ToolsDir
			CheckAuthenticodeSignature $MDEClientAnalyzerCommand
			&$MDEClientAnalyzerCommand >> $connectivityCheckFile
			Set-Location -Path $outputDir
		}
		elseif ($eulaAccepted -eq "Yes") {
			"`r`nConnectivity output, using psexec -s:" | Out-File $connectivityCheckFile -Append
			Write-Host "The tool checks connectivity to Microsoft Defender for Endpoint service URLs. This may take longer to run if URLs are blocked."
			Enter-CheckURL
			# Run the tool as interactive user (for authenticated proxy scenario)
			# Start-Process -wait -WindowStyle minimized $MDEClientAnalyzerCommand -WorkingDirectory $ToolsDir -RedirectStandardOutput $connectivityCheckUserFile
		}
		start-sleep 10
		EndTimedoutProcess "MDEClientAnalyzer" 5 
		if (test-path $URLCheckLog) {
			Get-Content -Path $URLCheckLog | Out-File $connectivityCheckFile -Append
			Get-Content -Path $psexeclog | Out-File $connectivityCheckFile -Append
		}
		ValidateURLs
	}
	elseif ($dotNet -ge $mindotNet) {
		Write-Host "The tool checks connectivity to Microsoft Defender for Endpoint service URLs. This may take longer to run if URLs are blocked."
		CheckAuthenticodeSignature $MDEClientAnalyzerPreviousVersionCommand
		# check if running with system context (i.e. script was most likely run remotely via "psexec.exe -s \\device command")
		if ($system) {
			Set-Location -Path $ToolsDir
			CheckAuthenticodeSignature $MDEClientAnalyzerPreviousVersionCommand
			$Global:connectivityresult = (&$MDEClientAnalyzerPreviousVersionCommand)
			Set-Location -Path $outputDir
		}
		elseif ($eulaAccepted -eq "Yes") {
			if (test-Path -path $PSExecCommand) {
				CheckAuthenticodeSignature $PSExecCommand
			}
			$Global:connectivityresult = (& $PSExecCommand -accepteula -s -nobanner -w "`"$($ToolsDir.TrimEnd('\'))`"" "$MDEClientAnalyzerPreviousVersionCommand" )
			# Run the tool as interactive user (for authenticated proxy scenario)
			Start-Process -wait -WindowStyle minimized $MDEClientAnalyzerPreviousVersionCommand -WorkingDirectory $ToolsDir -RedirectStandardOutput $connectivityCheckUserFile
			$Global:connectivityresultUser = (Get-Content $connectivityCheckUserFile)
		}
            
		#Run MMA Connectivity tool
		$MMATestProcess = "$env:ProgramFiles\Microsoft Monitoring Agent\Agent\TestCloudConnection.exe"
		if (Test-Path -path $MMATestProcess) {
			CheckAuthenticodeSignature $MMATestProcess
			$Global:TestOMSResult = &$MMATestProcess
		}
	} else {
		Write-Host -BackgroundColor Red -ForegroundColor Yellow "To run URI validation tool please install .NET framework 4.0  or higher"
		"To run URI validation tool please install .NET framework 4.0 or higher" | Out-File $connectivityCheckFile -Append
		$Global:connectivityresult = $false
		$Global:connectivityresultUser = $false
		$Global:TestOMSResult = $false
	}

	if ($OSPreviousVersion) {
		$HealthServiceDll = "$env:ProgramFiles\Microsoft Monitoring Agent\Agent\HealthService.dll"
		if (Test-Path -path $HealthServiceDll) {
			$healthserviceprops = @{
				Message = ""
				Valid   = $true
				Version = [string]((Get-ItemProperty -Path "$HealthServiceDll").VersionInfo).ProductMajorPart + '.' + [string]((Get-ItemProperty -Path "$HealthServiceDll").VersionInfo).ProductMinorPart + '.' + [string]((Get-ItemProperty -Path "$HealthServiceDll").VersionInfo).ProductBuildPart + '.' + [string]((Get-ItemProperty -Path "$HealthServiceDll").VersionInfo).FilePrivatePart
			}
			$Global:healthservicedll = new-object psobject -Property $healthserviceprops

			If ($OSBuild -eq "7601") {
				<#
				Supported versions for Windows Server 2008 R2 / 2008 / Windows 7
				x64 - 10.20.18029,  10.20.18038, 10.20.18040
				x86 - 10.20.18049
				#>
				if ($arch -like "*64*") {
					[version]$HealthServiceSupportedVersion = '10.20.18029'
				}
				else {
					[version]$HealthServiceSupportedVersion = '10.20.18049'
				}

				If ([version]$Global:healthservicedll.version -lt $HealthServiceSupportedVersion) {
					$Global:healthservicedll.Valid = $false
					$Global:healthservicedll.Message = "The Log Analytics Agent version installed on this device (" + $Global:healthservicedll.version + ") is deprecated as it does not support SHA2 for code signing.`r`n" `
						+ "Note that the older versions of the Log Analytics will no longer be supported and will stop sending data in a future timeframe. More information: https://aka.ms/LAAgentSHA2 `r`n" `
						+ "Please upgrade to the latest version:`r`n" `
						+ "- Windows 64-bit agent - https://go.microsoft.com/fwlink/?LinkId=828603 `r`n"`
						+ "- Windows 32-bit agent - https://go.microsoft.com/fwlink/?LinkId=828604"
				}
				else {
					$Global:healthservicedll.Message = "The version " + $Global:healthservicedll.version + " of HealthService.dll is supported"
				}
			}
		}
	}
	
	if ('$env:SystemRoot\\System32\wintrust.dll') {
		[version]$wintrustMinimumFileVersion = '6.1.7601.23971'
		$wintrustprops = @{
			Message = ""
			Valid   = $true
			Version = [string]((Get-ItemProperty -Path $env:SystemRoot\\System32\wintrust.dll).VersionInfo).ProductMajorPart + '.' + [string]((Get-ItemProperty -Path $env:SystemRoot\\System32\wintrust.dll).VersionInfo).ProductMinorPart + '.' + [string]((Get-ItemProperty -Path $env:SystemRoot\\System32\wintrust.dll).VersionInfo).ProductBuildPart + '.' + [string]((Get-ItemProperty -Path $env:SystemRoot\\System32\wintrust.dll).VersionInfo).FilePrivatePart
		}
		$Global:wintrustdll = new-object psobject -Property $wintrustprops

		if (([version]$Global:wintrustdll.version -lt $wintrustMinimumFileVersion) ) {
			$Global:wintrustdll.Valid = $false
			$Global:wintrustdll.Message = "Environment is not supported: " + [System.Environment]::OSVersion.VersionString + "`r`nMDE can't start - it requires wintrust.dll version $wintrustMinimumFileVersion or higher, while this device has version " + $wintrustdll.version + ". `r`n" `
				+ "You should install one of the following updates:`r`n" `
				+ "* KB4057400 - 2018-01-19 preview of monthly rollup.`r`n" `
				+ "* KB4074598 - 2018-02-13 monthly rollup.`r`n" `
				+ "* A later monthly rollup that supersedes them.`r`n"
		}
		else {
			$Global:wintrustdll.Message = "The version " + $Global:wintrustdll.version + " of wintrust.dll is supported"
		}
	}

	if (('$env:SystemRoot\\System32\tdh.dll')) {
		$tdhprops = @{
			Message = ""
			Valid   = $true
			Version = [string]((Get-ItemProperty -Path $env:SystemRoot\\System32\tdh.dll).VersionInfo).ProductMajorPart + '.' + [string]((Get-ItemProperty -Path $env:SystemRoot\\System32\tdh.dll).VersionInfo).ProductMinorPart + '.' + [string]((Get-ItemProperty -Path $env:SystemRoot\\System32\tdh.dll).VersionInfo).ProductBuildPart + '.' + [string]((Get-ItemProperty -Path $env:SystemRoot\\System32\tdh.dll).VersionInfo).FilePrivatePart
		}
		$Global:tdhdll = new-object psobject -Property $tdhprops
		
		if ($OSBuild -eq "9600") {
			[version]$gdrTdhMinimumFileVersion = '6.3.9600.17958'
		}
		else {
			[version]$gdrTdhMinimumFileVersion = '6.1.7601.18939'
			[version]$ldrMinimumFileVersion = '6.1.7601.22000'
			[version]$ldrTdhMinimumFileVersion = '6.1.7601.23142'
		}
	
		if ([version]$Global:tdhdll.Version -lt $gdrTdhMinimumFileVersion) {
			$Global:tdhdll.Valid = $false
			$Global:tdhdll.Message = "Environment is not supported: " + [System.Environment]::OSVersion.VersionString + "`r`nMDE can't start - it requires tdh.dll version $gdrTdhMinimumFileVersion or higher, while this device has version " + $tdhdll.version + ". `r`n" `
				+ "You should install the following update:`r`n" `
				+ "* KB3080149 - Update for customer experience and diagnostic telemetry.`r`n"
		}
		elseif ($OSBuild -eq "7601" -and [version]$Global:tdhdll.Version -ge $ldrMinimumFileVersion -and [version]$tdhdll.Version -lt $ldrTdhMinimumFileVersion) {
			$Global:tdhdll.Valid = $false
			$Global:tdhdll.Message = "Environment is not supported: " + [System.Environment]::OSVersion.VersionString + "`r`nMDE can't start - it requires tdh.dll version $ldrTdhMinimumFileVersion or higher, while this device has version " + $tdhdll.version + ". `r`n" `
				+ "You should install the following update:`r`n" `
				+ "* KB3080149 - Update for customer experience and diagnostic telemetry.`r`n"
		}
		else {
			$Global:tdhdll.Message = "The version " + $Global:tdhdll.version + " of tdh.dll is supported"
		}
	}

	$protocol = [Enum]::ToObject([System.Net.SecurityProtocolType], 3072)
	[string]$global:SSLProtocol = $null
	try {
		[System.Net.ServicePointManager]::SecurityProtocol = $protocol
	}
 catch [System.Management.Automation.SetValueInvocationException] {
		$global:SSLProtocol = "`r`nEnvironment is not supported , the missing KB must be installed`r`n"`
			+ "" + [System.Environment]::OSVersion.VersionString + ", MDE requires TLS 1.2 support in .NET framework 3.5.1, exception " + $_.Exception.Message + " . You should install the following updates:`n" `
			+ "* KB3154518 - Support for TLS System Default Versions included in the .NET Framework 3.5.1 on Windows 7 SP1 and Server 2008 R2 SP1`n"`
			+ "* .NET framework 4.0 or later.`n"`
			+ "########################################################################################################################" 
	}
 Catch [Exception] {
		$global:SSLProtocol = $_.Exception.Message
	}
}

function TestASRRules() {
	#Taken from: https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction#block-process-creations-originating-from-psexec-and-wmi-commands
	$ASRRuleBlockPsExec = "d1e49aac-8f56-4280-b9ba-993a6d77406c"

	$ASRRules = (Get-MpPreference).AttackSurfaceReductionRules_Ids
	$ASRActions = (Get-MpPreference).AttackSurfaceReductionRules_Actions
	if (($ASRRules) -and ($ASRActions) -and (!$system)) {
		Write-output "############################ ASR rule check ###############################" | Out-File $connectivityCheckFile -Append
		# Check for existance of 'Block' mode ASR rule that can block PsExec from running
		$RuleIndex = $ASRRules::indexof($ASRRules, $ASRRuleBlockPsExec)
		if (($RuleIndex -ne -1) -and ($ASRActions[$RuleIndex] -eq 1)) {
			# Check if exclusions on script path are set
			$ASRRulesExclusions = (Get-MpPreference).AttackSurfaceReductionOnlyExclusions
			if (($ASRRulesExclusions) -and (($ASRRulesExclusions -contains $PSScriptRoot + '\') -or ($ASRRulesExclusions -contains $PSScriptRoot))) {
				"ASR rule 'Block process creations originating from PSExec and WMI commands' exists in block mode, but script path is excluded as needed" | Out-File $connectivityCheckFile -Append
				Write-Host -BackgroundColor Green -ForegroundColor black "Script path is excluded from ASR rules so URL checks can run as expected."
			} 
			else {
				"ASR rule 'Block process creations originating from PSExec and WMI commands' exists on the device and is in Block mode" | Out-File $connectivityCheckFile -Append
				Write-Host -BackgroundColor Red -ForegroundColor Yellow "Please note that ASR rule 'Block process creations originating from PSExec and WMI commands' is enabled and can block this tool from performing network validation if no exclusion is set" 			
			}
		}
	}
}

#This function expects to receive the EventProvider, EventId and Error string and returns the error event if found
function Get-MatchingEvent($EventProvider, $EventID, $ErrorString) {
	$EventResult = Get-WinEvent -ProviderName $EventProvider -MaxEvents 1000 -ErrorAction SilentlyContinue `
	| Where-Object -Property Id -eq $EventID `
	| Where-Object { $_.Properties.Value -like "*$ErrorString*" } `
	| Sort-Object -Property TimeCreated -Unique `
	| Select-Object -L 1
	
	return $EventResult
}

function CheckProxySettings() {		
	$RegPathHKLM = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
	$RegPathHKU = "HKU:\S-1-5-18\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
	$RegPathHKCU = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
	$RegPathDefault = "HKU:\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"

	if (Get-RegistryValue -Path $RegPathHKLM -Value "ProxyServer") {
		"Proxy settings in device level were detected" | Out-File $connectivityCheckFile -append
		"The detected Proxy settings in device path (HKLM) are :  " + (Get-RegistryValue -Path $RegPathHKLM -Value "ProxyServer" ) | Out-File $connectivityCheckFile -append
		"ProxyEnable is set to :  " + (Get-RegistryValue -Path $RegPathHKLM -Value "ProxyEnable" ) | Out-File $connectivityCheckFile -append
	} 
	
	if (Get-RegistryValue -Path $RegPathHKU -Value "ProxyServer") {
		"Proxy settings in SYSTEM SID level were detected" | Out-File $connectivityCheckFile -append
		"The detected proxy settings in SYSTEM HKU path (S-1-5-18) are :  " + (Get-RegistryValue -Path $RegPathHKU -Value "ProxyServer" ) | Out-File $connectivityCheckFile -append
		"ProxyEnable is set to :  " + (Get-RegistryValue -Path $RegPathHKU -Value "ProxyEnable" ) | Out-File $connectivityCheckFile -append
	} 

	if (Get-RegistryValue -Path $RegPathHKCU -Value "ProxyServer") {
		"Proxy setting in current user level were detected" | Out-File $connectivityCheckFile -append
		"The detected proxy settings in current user path (HKCU) are :  " + (Get-RegistryValue -Path $RegPathHKCU -Value "ProxyServer" ) | Out-File $connectivityCheckFile -append
		"ProxyEnable is set to :  " + (Get-RegistryValue -Path $RegPathHKCU -Value "ProxyEnable" ) | Out-File $connectivityCheckFile -append
	}
	if (Get-RegistryValue -Path $RegPathDefault -Value "ProxyServer") {
		"Proxy setting in DEFAULT user level were detected" | Out-File $connectivityCheckFile -append
		"The detected proxy settings in the default user path (.DEFAULT) are :  " + (Get-RegistryValue -Path $RegPathDefault -Value "ProxyServer" ) | Out-File $connectivityCheckFile -append
		"ProxyEnable is set to :  " + (Get-RegistryValue -Path $RegPathDefault -Value "ProxyEnable" ) | Out-File $connectivityCheckFile -append
	}
	Check-Command-verified "bitsadmin.exe"
	"Proxy setting detected via bitsadmin: " + (&bitsadmin.exe /Util /GETIEPROXY LOCALSYSTEM) | Out-File $connectivityCheckFile -append
}
function GetAddRemovePrograms($regpath) {
	$programsArray = $regpath | ForEach-Object { New-Object PSObject -Property @{
			DisplayName     = $_.GetValue("DisplayName")
			DisplayVersion  = $_.GetValue("DisplayVersion")
			InstallLocation = $_.GetValue("InstallLocation")
			Publisher       = $_.GetValue("Publisher")
		} }
	$ProgramsArray | Where-Object { $_.DisplayName }
}

function FormatTimestamp($TimeStamp) {
	if ($TimeStamp) {
		return ([DateTime]::FromFiletime([Int64]::Parse($TimeStamp))).ToString("U")
	} 
	else {
		return "Unknown"
	}
}

function Dump-ConnectionStatus {
	"Last SevilleDiagTrack LastNormalUploadTime TimeStamp: " + (FormatTimestamp($LastCYBERConnected)) | Out-File $connectivityCheckFile -append
	"Last SevilleDiagTrack LastRealTimeUploadTime TimeStamp: " + (FormatTimestamp($LastCYBERRTConnected)) | Out-File $connectivityCheckFile -append
	"Last SevilleDiagTrack LastInvalidHttpCode: " + $LastInvalidHTTPcode | Out-File $connectivityCheckFile -append
}

function Get-DeviceInfo {
	Write-Report -section "devInfo" -subsection "deviceName" -displayname "Device name" -value $env:computername 
	Write-Report -section "devInfo" -subsection "OSName" -displayname "Device Operating System" -value $OSProductName 
	Write-Report -section "devInfo" -subsection "OSBuild" -displayname "OS build number" -value (([System.Environment]::OSVersion.VersionString) + "." + $MinorBuild)
	Write-Report -section "devInfo" -subsection "Edition" -displayname "OS Edition" -value $OSEditionName
	Write-Report -section "devInfo" -subsection "Architecture" -displayname "OS Architecture" -value $arch
	Write-Report -section "devInfo" -subsection "SystemBootTime" -displayname "SystemBootTime" -value $LastSystemBootTime
}

function Collect-RegValue {
	[string]$SQMMachineId = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\SQMClient" -Value "MachineId")
	[string]$SenseId = (Get-RegistryValue -Path "HKLM:\SOFTWARE\\Microsoft\Windows Advanced Threat Protection" -Value "SenseId")
	[string]$MachineAuthId = (Get-RegistryValue -Path "HKLM:\SOFTWARE\\Microsoft\Windows Advanced Threat Protection" -Value "C9D38BBB-E9DD-4B27-8E6F-7DE97E68DAB9")
	[string]$StateReg = (Get-RegistryValue -Path "HKLM:\SOFTWARE\\Microsoft\Windows Advanced Threat Protection" -Value "7DC0B629-D7F6-4DB3-9BF7-64D5AAF50F1A")
	[string]$DeviceTag = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\DeviceTagging" -Value "Group")
	[string]$GroupIds = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" -Value "GroupIds") 
	[string]$LastCnCConnected = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status" -Value LastConnected)
	[string]$PreferStaticProxyForHttpRequest = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" -Value PreferStaticProxyForHttpRequest)

	if ($SQMMachineId) {
		"SQM Machine Identifier from registry is:  " + $SQMMachineId | Out-File $connectivityCheckFile -append
	} else {
		"SQM Machine Identifier was not found in 'HKLM\SOFTWARE\Microsoft\SQMClient' key" | Out-File $connectivityCheckFile -append
	}

	if ($OSPreviousVersion) {
		$sensepr = Get-ChildItem -Path "C:\Program Files\Microsoft Monitoring Agent\Agent\Health Service State\Monitoring Host Temporary File*" -Filter mssenses.exe -Recurse -ErrorAction SilentlyContinue | Sort-Object -Property TimeCreated -Unique
	}
	elseif ($MDfWS) {
		$InstallPath = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection" -Value "InstallLocation")
		$sensepr = Join-Path $InstallPath "MsSense.exe"
	} else {
		$sensepr = (Get-item -Path "C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe" -ErrorAction SilentlyContinue)
	}

	Get-DeviceInfo
	if (!$SenseId) {
		# Option to get SenseID from event log as some older OS versions only post Sense Id to log
		$SenseId = (Get-WinEvent -ProviderName Microsoft-Windows-SENSE -ErrorAction SilentlyContinue | Where-Object -Property Id -eq 13 | Sort-Object -Property TimeCreated | Select-Object -L 1).Message			
	}
	if ($SenseId) {
		Write-Report -section "EDRCompInfo" -subsection "DeviceId" -displayname "Device ID" -value $SenseId 		

		$OrgId = (Get-RegistryValue -Path "HKLM:\SOFTWARE\\Microsoft\\Windows Advanced Threat Protection\Status" -Value "OrgID")
		Write-Report -section "EDRCompInfo" -subsection "OrgId" -displayname "Organization Id" -value $OrgId

		if ($sensepr) {
			[version]$Global:SenseVer = ([string](([System.IO.FileInfo]$sensepr).VersionInfo).ProductMajorPart + '.' + [string](([System.IO.FileInfo]$sensepr).VersionInfo).ProductMinorPart + '.' + [string](([System.IO.FileInfo]$sensepr).VersionInfo).ProductBuildPart + '.' + [string](([System.IO.FileInfo]$sensepr).VersionInfo).FilePrivatePart)
			Write-Report -section "EDRCompInfo" -subsection "SenseVersion" -displayname "Sense version" -value $Global:SenseVer 
		}
		$SenseConfigVer = (Get-RegistryValue -Path "HKLM:\SOFTWARE\\Microsoft\\Windows Advanced Threat Protection\Status" -Value "ConfigurationVersion" ) 
		if ($SenseConfigVer -like "*-*") {
			$SenseConfigVer = $SenseConfigVer.split('-')[0] 
		}
		Write-Report -section "EDRCompInfo" -subsection "SenseConfigVersion" -displayname "Sense Configuration version" -value $SenseConfigVer 

		"Sense GUID is: " + (Get-RegistryValue -Path "HKLM:\SOFTWARE\\Microsoft\\Windows Advanced Threat Protection" -Value "senseGuid") | Out-File $connectivityCheckFile -append
		if ($DeviceTag -ne $False) {
			"Optional Sense DeviceTag is: " + $DeviceTag | Out-File $connectivityCheckFile -append
		}		
		if ($GroupIds) {
			"Optional Sense GroupIds is: " + $GroupIds | Out-File $connectivityCheckFile -append
		}
		if ($PreferStaticProxyForHttpRequest) {
			"Optional PreferStaticProxyForHttpRequest setting is: " + $PreferStaticProxyForHttpRequest | Out-File $connectivityCheckFile -append
		}
		if (($LastCnCConnected) -and (!$ASM)) {
			"Last Sense Seen TimeStamp is: " + (FormatTimestamp($LastCnCConnected)) | Out-File $connectivityCheckFile -append
		}
	}
	if ($MachineAuthId) {
		Write-Report -section "EDRCompInfo" -subsection "MachineAuthId" -displayname "MachineAuth ID" -value $MachineAuthId
	}
	if ($StateReg) {
		Write-Report -section "EDRCompInfo" -subsection "StateReg" -displayname "Anti-Spoofing State GUID" -value $StateReg 
	}
	if (!$IsOnboarded) {
		"Device is: not onboarded" | Out-File $connectivityCheckFile -append
	}
}

Function StartGet-MSInfo ([boolean]$NFO = $true, [boolean]$TXT = $true, [string]$OutputLocation = $PWD.Path, [string]$Suffix = '') {
	$Process = "msinfo32.exe"
	
	if (test-path (join-path ([Environment]::GetFolderPath("System")) $Process)) {
		$ProcessPath = (join-path ([Environment]::GetFolderPath("System")) $Process)
	}
 elseif (test-path (join-path ([Environment]::GetFolderPath("CommonProgramFiles")) "Microsoft Shared\MSInfo\$Process")) {
		$ProcessPath = (join-path ([Environment]::GetFolderPath("CommonProgramFiles")) "Microsoft Shared\MSInfo\$Process")
	}
 else {
		Check-Command-verified "cmd.exe"
		$ProcessPath = "cmd.exe /c start /wait $Process"
	}
	if ($TXT) {
		$InfoFile = Join-Path -Path $OutputLocation -ChildPath ("msinfo32" + $Suffix + ".txt")
		CheckAuthenticodeSignature $ProcessPath
		&$ProcessPath /report "$InfoFile"
	}
	if ($NFO) {
		$InfoFile = Join-Path -Path $OutputLocation -ChildPath ("msinfo32" + $Suffix + ".nfo")
		CheckAuthenticodeSignature $ProcessPath
		&$ProcessPath /nfo "$InfoFile"
	}
}

function EndTimedoutProcess ($process, $ProcessWaitMin) {
	$proc = Get-Process $process -EA SilentlyContinue
	if ($proc) {
		Write-Host "Waiting max $ProcessWaitMin minutes on $process processes to complete "
		Wait-Process -InputObject $proc -Timeout ($ProcessWaitMin * 60) -EA SilentlyContinue
		$ProcessToEnd = Get-Process | Where-Object { $_.Name -eq "$process" } -EA SilentlyContinue
		if ($ProcessToEnd -ne $null) {
			Write-Host "timeout reached ..."
			foreach ($prc in $ProcessToEnd) { stop-Process $prc -Force -EA SilentlyContinue }
		}
	}
}

function Process-XSLT {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][String]$XmlPath, 
		[Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][String]$XslPath,
		[Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][String]$HtmlOutput )

	Try {
		If ((Test-path($XmlPath)) -and (Test-path($XslPath))) {
			$myXslCompiledTransfrom = new-object System.Xml.Xsl.XslCompiledTransform
			$xsltArgList = New-Object System.Xml.Xsl.XsltArgumentList

			$myXslCompiledTransfrom.Load($XslPath)
			$xmlWriter = [System.Xml.XmlWriter]::Create($HtmlOutput)
		
			$myXslCompiledTransfrom.Transform($XmlPath, $xsltArgList, $xmlWriter)
	
			$xmlWriter.Flush()
			$xmlWriter.Close()

			return $True
		} 
	}
 Catch {
		return $False
	}
}

function GenerateHealthCheckReport() {
	# Save XML log file
	$script:xmlDoc.Save($XmlLogFile)

	CheckHashFile "$XslFile" "7F801B73C2E0D1A43EF9915328881A85D1EE7ADDBC31273CCD72D1C81CB2B258"
	# Transform XML to HTML based using XSLT
	$Result = Process-XSLT -XmlPath $XmlLogFile -XslPath $XslFile -HtmlOutput $HtmOutputfile
	If (!$Result) {
		"Unable to generate HTML file" | Out-File $connectivityCheckFile -append
	}
}

function WriteReport($id, $CheckresultInsertions, $GuidanceRInsertions) {
	$CurrEvent = $ResourcesOfEvents.$id
	$i = 1
	$CurrEvent, $i = UpdateInsertion $CurrEvent $CheckresultInsertions $i "checkresult"
	$CurrEvent, $i = UpdateInsertion $CurrEvent $GuidanceRInsertions $i "guidance"
	$CurrEvent.checkresult = [regex]::replace($CurrEvent.checkresult, '\n', '<br>')
	$CurrEvent.guidance = [regex]::replace($CurrEvent.guidance, '\n', '<br>')
	Write-ReportEvent -section "events" -severity $CurrEvent.severity -category $CurrEvent.category -check $CurrEvent.check -id $id -checkresult $CurrEvent.checkresult -guidance $CurrEvent.guidance
}

function UpdateInsertion($CurrEvent, $Insertions, $i, $id) {
	If ($Insertions.Count -gt 0) {
		Foreach ($insert in $Insertions) {
			$ind = '%' + "$i"
			$CurrEvent.$id = [regex]::replace($CurrEvent.$id, $ind, $insert)
			$i += 1
		}	
	}
	return $CurrEvent, $i
}

function CheckExpirationCertUtil($IsDisabled, $TestName, $RootToCheck) {
	Check-Command-verified "certutil.exe"
	$CertResults = &certutil -verifyctl $TestName $RootToCheck | findstr /i SignerExpiration
	"`n`nCommand:`n`tcertutil -verifyctl $TestName | findstr /i SignerExpiration `nResults:`n`t" + $CertResults | Out-File $CertSignerResults -append

	#Get the number of days from $CertResults: 'SignerExpiration = "12/2/2021 11:25 PM", "273.5 Days"'
	$ExpirationTime = $CertResults.split('"')[3].split(" ")[0]
	#Case there is ',' instead '.'
	$ExpirationTime = [double]($ExpirationTime.replace(',', '.'))
	If ($ExpirationTime -le 0) {
		#$days = [string]($ExpirationTime * (-1))
		If ($IsDisabled) {
			#WriteReport 121013 @(@($days, $CertSignerResults)) @()
		}
		else {
			#WriteReport 121014 @(@($days, $CertSignerResults)) @()
		}
	}
}

function CheckAuthenticodeSignature($pathToCheck) {
	if (test-path $resultOutputDir -ErrorAction SilentlyContinue) {
		$issuerInfo = "$resultOutputDir\issuerInfo.txt"
	} else {
		$issuerInfo = "$outputDir\issuerInfo.txt"
	}
	if ($pathToCheck) {
		if (Test-Path -path $pathToCheck -ErrorAction SilentlyContinue) {
			$AuthenticodeSig = (Get-AuthenticodeSignature -FilePath $pathToCheck)
			$cert = $AuthenticodeSig.SignerCertificate
			$FileInfo = (get-command $pathToCheck).FileVersionInfo			
			$issuer = $cert.Issuer
			#OS is older than 2016 and some built-in processes will not be signed
			if (($OSBuild -lt 14393) -and (!$AuthenticodeSig.SignerCertificate)) {
				if (($FileInfo.CompanyName -eq "Microsoft Corporation")) {
					return
				}
				else {
					Write-Error "Script execution terminated because a process or script that does not have any signature was detected" | Out-File $issuerInfo -append
					$pathToCheck | Out-File $issuerInfo -append
					$AuthenticodeSig | Format-List * | Out-File $issuerInfo -append
					$cert | Format-List * | Out-File $issuerInfo -append
					[Environment]::Exit(1)
				}
			}
			#check if valid
			if ($AuthenticodeSig.Status -ne "Valid") {
				Write-Error "Script execution terminated because a process or script that does not have a valid Signature was detected" | Out-File $issuerInfo -append
				$pathToCheck | Out-File $issuerInfo -append
				$AuthenticodeSig | Format-List * | Out-File $issuerInfo -append
				$cert | Format-List * | Out-File $issuerInfo -append
				[Environment]::Exit(1)
			}
			#check issuer
			if (($issuer -ne "CN=Microsoft Code Signing PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US") -and ($issuer -ne "CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US") -and ($issuer -ne "CN=Microsoft Code Signing PCA, O=Microsoft Corporation, L=Redmond, S=Washington, C=US") -and ($issuer -ne "CN=Microsoft Code Signing PCA 2010, O=Microsoft Corporation, L=Redmond, S=Washington, C=US") -and ($issuer -ne "CN=Microsoft Development PCA 2014, O=Microsoft Corporation, L=Redmond, S=Washington, C=US")) {
				Write-Error "Script execution terminated because a process or script that is not Microsoft signed was detected" | Out-File $issuerInfo -append
				$pathToCheck | Out-File $issuerInfo -append
				$AuthenticodeSig | Format-List * | Out-File $issuerInfo -append
				$cert | Format-List * | Out-File $issuerInfo -append
				[Environment]::Exit(1)
			}	
			if ($AuthenticodeSig.IsOSBinary -ne "True") {
				#If revocation is offline then test below will fail
				$IsOnline = (Get-NetConnectionProfile).IPv4Connectivity -like "*Internet*"
				$EKUArray = @('1.3.6.1.5.5.7.3.3', '1.3.6.1.4.1.311.76.47.1')
				if ($IsOnline) {
					$IsWindowsSystemComponent = (Test-Certificate -Cert $cert -EKU "1.3.6.1.4.1.311.10.3.6" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -WarningVariable OsCertWarnVar -ErrorVariable OsCertErrVar)
					$IsMicrosoftPublisher = (Test-Certificate -Cert $cert -EKU "1.3.6.1.4.1.311.76.8.1" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -WarningVariable MsPublisherWarnVar -ErrorVariable MsPublisherErrVar)
					$TrustedEKU = (Test-Certificate -Cert $cert -EKU $EKUArray -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -WarningVariable EKUWarnVar -ErrorVariable EKUErrVar)
					if (($IsWindowsSystemComponent -eq $False) -and ($IsMicrosoftPublisher -eq $False) -and ($TrustedEKU -eq $False)) {
						#Defender AV and some OS processes will have an old signature if older version is installed
						#Ignore if cert is OK and only signature is old
						if (($OsCertWarnVar -like "*CERT_TRUST_IS_NOT_TIME_VALID*") -or ($MsPublisherWarnVar -like "*CERT_TRUST_IS_NOT_TIME_VALID*") -or ($OsCertWarnVar -like "*CERT_TRUST_IS_OFFLINE_REVOCATION*") -or ($MsPublisherWarnVar -like "CERT_TRUST_IS_OFFLINE_REVOCATION")) {
							return
						}
						Write-Error "Script execution terminated because the process or script certificate failed trust check" | Out-File $issuerInfo -append
						$pathToCheck | Out-File $issuerInfo -append
						$AuthenticodeSig | Format-List * | Out-File $issuerInfo -append
						$cert | Format-List * | Out-File $issuerInfo -append
						[Environment]::Exit(1)
					}
				}
			}
		}
	 else {
			Write-Error ("Path " + $pathToCheck + " was not found") | Out-File $issuerInfo -append
		}
	}
}

function CheckHashFile($filePath, $hash) {
	if (test-path $filePath) {
		$fileHash = Get-FileHash -Path $filePath
		if ($fileHash.Hash -ne $hash) {
			Write-Error "Script execution terminated because hash did not match expected value. Expected value: $hash"
			[Environment]::Exit(1)
		}
	}
}

function NTFSSecurityAccess($resultOutputDir) {
	Check-Command-verified "takeown.exe"
	#take ownership
	Start-Process -wait -WindowStyle minimized Takeown.exe -ArgumentList "/f `"$resultOutputDir`" /r /d y"
	Check-Command-verified "icacls.exe"
	#Prevent inheritance
	Start-Process -wait -WindowStyle minimized icacls.exe -ArgumentList "`"$resultOutputDir`" /inheritance:r"
	Check-Command-verified "icacls.exe"
	#Allow Access to Administrators
	Start-Process -wait -WindowStyle minimized icacls.exe -ArgumentList "`"$resultOutputDir`" /grant `"Administrators`":(OI)(CI)F /t /q"
	Check-Command-verified "icacls.exe"
	#Allow Access to Creator owner 
	Start-Process -wait -WindowStyle minimized icacls.exe -ArgumentList "`"$resultOutputDir`" /grant `"Creator Owner`":(OI)(CI)F /t /q"
	Check-Command-verified "icacls.exe"
	#Allow Access to SYSTEM
	Start-Process -wait -WindowStyle minimized icacls.exe -ArgumentList "`"$resultOutputDir`" /grant `"NT AUTHORITY\SYSTEM`":(OI)(CI)F /t /q"
	Check-Command-verified "icacls.exe"
	if (!$System) {
		#Allow curent user access
		Start-Process -wait -WindowStyle minimized icacls.exe -ArgumentList "`"$resultOutputDir`" /grant `"$context`":(OI)(CI)F /t /q"
	}
	
}

#gets path of command and check signature
function Check-Command-verified($checkCommand) {
	$command = Get-Command $CheckCommand -ErrorAction SilentlyContinue
	CheckAuthenticodeSignature $command.path
}

function get-MdeConfigMgrLog() {
	# folder for SIMA logs and info
	New-Item -ItemType Directory -Path "$resultOutputDir\MdeConfigMgrLogs" -ErrorAction SilentlyContinue | out-Null
	$MdeConfigMgrRegInfo = "$resultOutputDir\MdeConfigMgrLogs\MdeConfigMgrRegInfo.txt"
	# reg info collections
	"please find reg info for MdeConfigMgr flow On : " + $ScriptRunTime + "`n" | Out-File $MdeConfigMgrRegInfo
	"EnrollmentStatus : " + (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\SenseCM\" -Value EnrollmentStatus) | Out-File $MdeConfigMgrRegInfo -Append
	"TenantId : " + (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\SenseCM\" -Value TenantId) | Out-File $MdeConfigMgrRegInfo -Append
	"DeviceId : " + (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\SenseCM\" -Value DeviceId) | Out-File $MdeConfigMgrRegInfo -Append
	"EnrollmentPayload : " + (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\SenseCM\" -Value EnrollmentPayload) | Out-File $MdeConfigMgrRegInfo -Append
	"MemConfiguration : " + (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\SenseCM\" -Value MemConfiguration) | Out-File $MdeConfigMgrRegInfo -Append
	"LastCheckinAttempt : " + (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\SenseCM\" -Value LastCheckinAttempt) | Out-File $MdeConfigMgrRegInfo -Append
	"LastCheckinSuccess : " + (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\SenseCM\" -Value LastCheckinAttempt) | Out-File $MdeConfigMgrRegInfo -Append
	"SystemManufacturer : " + (Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation\" -Value SystemManufacturer) | Out-File $MdeConfigMgrRegInfo -Append
	"SystemProductName : " + (Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation\" -Value SystemProductName) | Out-File $MdeConfigMgrRegInfo -Append
	"ProductName : " + (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\" -Value ProductName) | Out-File $MdeConfigMgrRegInfo -Append
	"UBR : " + (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\" -Value UBR) | Out-File $MdeConfigMgrRegInfo -Append
	"OnboardedInfo : " | Out-File $MdeConfigMgrRegInfo -Append
	(Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\" -Value OnboardedInfo) |  ConvertFrom-Json | Select-Object body | Out-File $MdeConfigMgrRegInfo -Append
	"SenseCmConfiguration : " | Out-File $MdeConfigMgrRegInfo -Append
	(Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\" -Value SenseCmConfiguration) |  ConvertFrom-Json | Out-File $MdeConfigMgrRegInfo -Append
	"NextVersion : " + (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\" -Value NextVersion) | Out-File $MdeConfigMgrRegInfo -Append
	"InvalidVersion : " + (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\" -Value InvalidVersion) | Out-File $MdeConfigMgrRegInfo -Append
	"SwitchStatus : " + (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\" -Value SwitchStatus) | Out-File $MdeConfigMgrRegInfo -Append
	"InstallLocation : " + (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\" -Value InstallLocation) | Out-File $MdeConfigMgrRegInfo -Append
	"NewPlatform : " + (Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\" -Value NewPlatform) | Out-File $MdeConfigMgrRegInfo -Append
	"MsSensePath : " + (Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\sense" -Value ImagePath) | Out-File $MdeConfigMgrRegInfo -Append
	"MsSecFltPath : " + (Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\MsSecFlt" -Value ImagePath) | Out-File $MdeConfigMgrRegInfo -Append

	# collect event logs
	if (Test-Path -Path $env:SystemRoot\System32\'Winevt\Logs\Microsoft-Windows-AADRT%4Admin.evtx') {
		Copy-Item -path $env:SystemRoot\System32\Winevt\Logs\Microsoft-Windows-AADRT%4Admin.evtx -Destination $resultOutputDir\EventLogs\AADRT-Admin.evtx
	}

	if (Test-Path -Path $env:SystemRoot\System32\'Winevt\Logs\Microsoft-Windows-AAD%4Operational.evtx') {
		Copy-Item -path $env:SystemRoot\System32\Winevt\Logs\Microsoft-Windows-AAD%4Operational.evtx -Destination $resultOutputDir\EventLogs\AAD-Operational.evtx
	}

	# collect additional files
	if (test-path -Path $env:SystemRoot\Temp\MpSigStub.log) {
		Copy-Item -path $env:SystemRoot\Temp\MpSigStub.log -Destination $resultOutputDir\EventLogs\MpSigStub.log
	}

	#collect sense CM data folder
	if (($eulaAccepted -eq "Yes") -and (!$system)) {
		$PSExecCommand = Join-Path $ToolsDir "PsExec.exe"
		if (test-Path -path $PSExecCommand) {
			CheckAuthenticodeSignature $PSExecCommand
		}
		Check-Command-verified "Robocopy.exe"
		Start-Process -PassThru -wait -WindowStyle minimized $PSExecCommand -ArgumentList "-accepteula -nobanner -s robocopy.exe `"$env:ProgramData\Microsoft\Windows Defender Advanced Threat Protection\SenseCM`" `"$resultOutputDir\MdeConfigMgrLogs`" /E /ZB /w:1 /r:1  /log:`"$resultOutputDir\MdeConfigMgrLogs\copy.log`"" | Out-Null
	}
 elseif ($system) {
		Check-Command-verified "Robocopy.exe"
		Start-Process -PassThru -wait -WindowStyle minimized Robocopy.exe -ArgumentList "`"$env:ProgramData\Microsoft\Windows Defender Advanced Threat Protection\SenseCM`" `"$resultOutputDir\MdeConfigMgrLogs`" /E /ZB /w:1 /r:1  /log:`"$resultOutputDir\MdeConfigMgrLogs\copy.log`""  | Out-Null
	}
}

# Return the information about Sense Configuration Manager a PSObject.
Function Get-SenseCMInfo () {
	$SenseCMInfoObj = New-Object -TypeName PSObject

	$SenseCMRegPath = "HKLM:\SOFTWARE\Microsoft\SenseCM\"
	
	# Check the device's enrollment status
	$EnrollmentStatusId = (Get-RegistryValue -Path $SenseCMRegPath -Value "EnrollmentStatus" -ErrorAction SilentlyContinue)
	if ($EnrollmentStatusId) {
		Add-Member -InputObject $SenseCMInfoObj -MemberType NoteProperty -Name "EnrollmentStatusId" -Value $EnrollmentStatusId -ErrorAction SilentlyContinue
		Add-Member -InputObject $SenseCMInfoObj -MemberType NoteProperty -Name "EnrollmentStatusReportId" -Value "" -ErrorAction SilentlyContinue
		switch ($EnrollmentStatusId) {
			1 {$EnrollmentStatusText = "Device is enrolled to AAD and MEM"}
			2 {$EnrollmentStatusText = "Device is not enrolled and was never enrolled"}
			{(($_ -eq 3) -or ($_ -eq 21))} {$EnrollmentStatusText = "Device is managed by MDM Agent"}
			{(($_ -eq 4) -or ($_ -eq 22))} {$EnrollmentStatusText = "Device is managed by SCCM Agent"}

			{(($_ -ge 5) -and ($_ -le 7)) -or ($_ -eq 9) -or (($_ -ge 11) -and ($_ -le 12)) -or (($_ -ge 26) -and ($_ -le 33))} {$EnrollmentStatusText = "General error";$SenseCMInfoObj.EnrollmentStatusReportId = "122022"}
			{(($_ -eq 8) -or ($_ -eq 44))} {$EnrollmentStatusText = "Microsoft Endpoint Manager Configuration issue"; $SenseCMInfoObj.EnrollmentStatusReportId = "122023"}  
			{(($_ -ge 13) -and ($_ -le 14)) -or ($_ -eq 20) -or ($_ -eq 24) -or ($_ -eq 25)} {$EnrollmentStatusText = "Connectivity issue";$SenseCMInfoObj.EnrollmentStatusReportId = "122024"}
			{(($_ -eq 10) -or ($_ -eq 42))} {$EnrollmentStatusText = "General Hybrid join failure"; $SenseCMInfoObj.EnrollmentStatusReportId = "122025"}  
			15 {$EnrollmentStatusText = "Tenant mismatch"; $SenseCMInfoObj.EnrollmentStatusReportId = "122026"}
			{(($_ -eq 16) -or ($_ -eq 17))} {$EnrollmentStatusText = "Hybrid error - Service Connection Point"; $SenseCMInfoObj.EnrollmentStatusReportId = "122027"}  
			18 {$EnrollmentStatusText = "Certificate error"; $SenseCMInfoObj.EnrollmentStatusReportId = "122028"}
			{(($_ -eq 36) -or ($_ -eq 37))} {$EnrollmentStatusText = "AAD Connect misconfiguration"; $SenseCMInfoObj.EnrollmentStatusReportId = "122029"}  
			{(($_ -eq 38) -or ($_ -eq 41))} {$EnrollmentStatusText = "DNS error"; $SenseCMInfoObj.EnrollmentStatusReportId = "122030"}  
			40 {$EnrollmentStatusText = "Clock sync issue"; $SenseCMInfoObj.EnrollmentStatusReportId = "122031"}
			43 {$EnrollmentStatusText = "MDE and ConfigMgr"; $SenseCMInfoObj.EnrollmentStatusReportId = "120031"}
			default {
				$EnrollmentStatusText = "Unknown State"
			}
		}

		Add-Member -InputObject $SenseCMInfoObj -MemberType NoteProperty -Name "EnrollmentStatusText" -Value ($EnrollmentStatusText+" ("+$EnrollmentStatusId+")") -ErrorAction SilentlyContinue
		$DeviceId =  (Get-RegistryValue -Path $SenseCMRegPath -Value DeviceId -ErrorAction SilentlyContinue)
		if ($DeviceId) {$DeviceId = $DeviceId.Tolower()}
		
		Add-Member -InputObject $SenseCMInfoObj -MemberType NoteProperty -Name "AADDeviceId" -Value $DeviceId -ErrorAction SilentlyContinue
		Add-Member -InputObject $SenseCMInfoObj -MemberType NoteProperty -Name "TenantId" -Value (Get-RegistryValue -Path $SenseCMRegPath -Value TenantId) -ErrorAction SilentlyContinue
		
		$IntuneDeviceID = ((Get-RegistryValue -Path $SenseCMRegPath -Value EnrollmentPayload -ErrorAction SilentlyContinue) |  ConvertFrom-Json -ErrorAction SilentlyContinue).intuneDeviceId
		Add-Member -InputObject $SenseCMInfoObj -MemberType NoteProperty -Name "IntuneDeviceID" -Value $IntuneDeviceID -ErrorAction SilentlyContinue
	}

	return $SenseCMInfoObj
}


# Return the output of dsregcmd /status as a PSObject.
Function Get-DsRegStatus () {
	if (test-path -path $env:windir\system32\dsregcmd.exe) {
		Check-Command-verified "dsregcmd.exe"
		$dsregcmd = &dsregcmd /status
		
		# Dump dsregcmd info to results
		$dsregcmd  | Out-File "$resultOutputDir\SystemInfoLogs\dsregcmd.txt"
	
		 $o = New-Object -TypeName PSObject
		 foreach($line in $dsregcmd) {
			  if ($line -like "| *") {
				   if (-not [String]::IsNullOrWhiteSpace($currentSection) -and $null -ne $so) {
						Add-Member -InputObject $o -MemberType NoteProperty -Name $currentSection -Value $so -ErrorAction SilentlyContinue
				   }
				   $currentSection = $line.Replace("|","").Replace(" ","").Trim()
				   $so = New-Object -TypeName PSObject
			  } elseif ($line -match " *[A-z]+ : [A-z0-9\{\}]+ *") {
				   Add-Member -InputObject $so -MemberType NoteProperty -Name (([String]$line).Trim() -split " : ")[0] -Value (([String]$line).Trim() -split " : ")[1] -ErrorAction SilentlyContinue
			  }
		 }
		 if (-not [String]::IsNullOrWhiteSpace($currentSection) -and $null -ne $so) {
			  Add-Member -InputObject $o -MemberType NoteProperty -Name $currentSection -Value $so -ErrorAction SilentlyContinue
		 }
		return $o
	}
}

# Get Windows 10 MDM Enrollment Status.
function Get-MDMEnrollmentStatus {
	#Locate correct Enrollment Key
	$EnrollmentKey = Get-Item -Path HKLM:\SOFTWARE\Microsoft\Enrollments\* | Get-ItemProperty | Where-Object -FilterScript {$null -ne $_.UPN}
	
	if ($EnrollmentKey) {
		# Translate the MDM Enrollment Type in a readable string.
		Switch ($EnrollmentKey.EnrollmentType) {
		0 {$EnrollmentTypeText = "Enrollment was not started"}
		6 {$EnrollmentTypeText = "MDM enrolled"}
		13 {$EnrollmentTypeText = "Azure AD joined"}
		}
		Add-Member -InputObject $EnrollmentKey -MemberType NoteProperty -Name EnrollmentTypeText -Value $EnrollmentTypeText
	} else {
		# Write-Error "Device is not enrolled to MDM."
		$EnrollmentKey = New-Object -TypeName PSObject
		Add-Member -InputObject $EnrollmentKey -MemberType NoteProperty -Name EnrollmentTypeText -Value "Not enrolled"
	}

	# Return 'Not enrolled' if Device is not enrolled to an MDM.
	return $EnrollmentKey
}

# TODO: Report the connectivity failure
function CheckDCConnecvitiy {
	$ErrorActionPreference = "SilentlyContinue"

    $DCName = ""
	Check-Command-verified "nltest.exe"
    $DCTest = nltest /dsgetdc:
    $DCName = $DCTest | Select-String DC | Select-Object -first 1
    $DCName = ($DCName.tostring() -split "DC: \\")[1].trim()

    if (($DCName.length) -eq 0) {
		return $False		
	} else {
		return $True		
	}
}

function Get-SCPConfiguration {
	$SCPConfiguration = New-Object -TypeName PSObject
	Add-Member -InputObject $SCPConfiguration -MemberType NoteProperty -Name ResultID -Value "" -ErrorAction SilentlyContinue

	$CDJReg = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ\AAD -ErrorAction SilentlyContinue
	if (((($CDJReg.TenantId).Length) -eq 0) -AND ((($CDJReg.TenantName).Length) -eq 0)) {
		# No client-side registry setting were found for SCP, checking against DC
		if (CheckDCConnecvitiy) {
			$Root = [ADSI]"LDAP://RootDSE"
			$ConfigurationName = $Root.rootDomainNamingContext
			if (($ConfigurationName.length) -eq 0) {
				$SCPConfiguration.ResultID = 121016
			} else {
				$scp = New-Object System.DirectoryServices.DirectoryEntry;
				$scp.Path = "LDAP://CN=62a0ff2e-97b9-4513-943f-0d221bd30080,CN=Device Registration Configuration,CN=Services,CN=Configuration," + $ConfigurationName;
				if ($scp.Keywords -ne $null){
					Add-Member -InputObject $SCPConfiguration -MemberType NoteProperty -Name ConfigType -Value "Domain" -ErrorAction SilentlyContinue
					if ($scp.Keywords -like ("*enterpriseDrsName*")) {
						# Enterprise DRS was found
						$SCPConfiguration.ResultID = 121017
						$SCPConfiguration.TenantName = $scp.Keywords.ToString()
					} else {
						Add-Member -InputObject $SCPConfiguration -MemberType NoteProperty -Name TenantName -Value (($scp.Keywords[0].tostring() -split ":")[1].trim()) -ErrorAction SilentlyContinue
						Add-Member -InputObject $SCPConfiguration -MemberType NoteProperty -Name TenantId -Value (($scp.Keywords[1].tostring() -split ":")[1].trim()) -ErrorAction SilentlyContinue
					}
				} Else {
					$SCPConfiguration.ResultID = 121018
				}
			}
		} Else {
			$SCPConfiguration.ResultID = 121019
		}
	} else {
		# Client-side registry setting were found for SCP
		Add-Member -InputObject $SCPConfiguration -MemberType NoteProperty -Name ConfigType -Value "Client" -ErrorAction SilentlyContinue
		Add-Member -InputObject $SCPConfiguration -MemberType NoteProperty -Name TenantName -Value ($CDJReg.TenantName) -ErrorAction SilentlyContinue
		Add-Member -InputObject $SCPConfiguration -MemberType NoteProperty -Name TenantId -Value ($CDJReg.TenantId) -ErrorAction SilentlyContinue
	}

	return $SCPConfiguration
}
# TODO: Connectivity checks to DRS 


function ConnecttoAzureAD {
    Write-Host ''
    Write-Host "Checking if there is a valid Access Token..." -ForegroundColor Yellow
    Write-Log -Message "Checking if there is a valid Access Token..."
    $headers = @{ 
                'Content-Type'  = "application\json"
                'Authorization' = "Bearer $global:accesstoken"
                }
    $GraphLink = "https://graph.microsoft.com/v1.0/domains"
    $GraphResult=""
    $GraphResult = (Invoke-WebRequest -Headers $Headers -Uri $GraphLink -UseBasicParsing -Method "GET" -ContentType "application/json").Content | ConvertFrom-Json

    if ($GraphResult.value.Count)
    {
            $headers = @{ 
            'Content-Type'  = "application\json"
            'Authorization' = "Bearer $global:accesstoken"
            }
            $GraphLink = "https://graph.microsoft.com/v1.0/me"
            $GraphResult=""
            $GraphResult = (Invoke-WebRequest -Headers $Headers -Uri $GraphLink -UseBasicParsing -Method "GET" -ContentType "application/json").Content | ConvertFrom-Json
            $User_DisplayName=$GraphResult.displayName
            $User_UPN=$GraphResult.userPrincipalName
            Write-Host "There is a valid Access Token for user: $User_DisplayName, UPN: $User_UPN" -ForegroundColor Green
            $msg="There is a valid Access Token for user: $User_DisplayName, UPN: $User_UPN" 
            Write-Log -Message $msg

    } else {
        Write-Host "There no valid Access Token, please sign-in to get an Access Token" -ForegroundColor Yellow
        Write-Log -Message "There no valid Access Token, please sign-in to get an Access Token"
        $global:accesstoken = Connect-AzureDevicelogin
        ''
        if ($global:accesstoken.Length -ge 1){
            $headers = @{ 
            'Content-Type'  = "application\json"
            'Authorization' = "Bearer $global:accesstoken"
            }
            $GraphLink = "https://graph.microsoft.com/v1.0/me"
            $GraphResult=""
            $GraphResult = (Invoke-WebRequest -Headers $Headers -Uri $GraphLink -UseBasicParsing -Method "GET" -ContentType "application/json").Content | ConvertFrom-Json
            $User_DisplayName=$GraphResult.displayName
            $User_UPN=$GraphResult.userPrincipalName
            Write-Host "You signed-in successfully, and got an Access Token for user: $User_DisplayName, UPN: $User_UPN" -ForegroundColor Green
            $msg="You signed-in successfully, and got an Access Token for user: $User_DisplayName, UPN: $User_UPN" 
            Write-Log -Message $msg
        }
    }
}

function CheckAzureADDeviceHealth ($DeviceID) {
	ConnecttoAzureAD

	$DeviceHealth = New-Object -TypeName PSObject

    $headers = @{ 
                'Content-Type'  = "application\json"
                'Authorization' = "Bearer $global:accesstoken"
                }

    $GraphLink = "https://graph.microsoft.com/v1.0/devices?`$filter=deviceId eq '$DeviceID'"
    try {
        $GraphResult = Invoke-WebRequest -Headers $Headers -Uri $GraphLink -UseBasicParsing -Method "GET" -ContentType "application/json"
        $AADDevice = $GraphResult.Content | ConvertFrom-Json

        if ($AADDevice.value.Count -ge 1) {
			# Device was found    
			Add-Member -InputObject $DeviceHealth -MemberType NoteProperty -Name DeviceExists -Value $True -ErrorAction SilentlyContinue
			Add-Member -InputObject $DeviceHealth -MemberType NoteProperty -Name DeviceEnabled -Value $AADDevice.value.accountEnabled -ErrorAction SilentlyContinue

			# Check if device in Stale state
			$LastLogonTimestamp = $AADDevice.value.approximateLastSignInDateTime
			Add-Member -InputObject $DeviceHealth -MemberType NoteProperty -Name LastLogonTimestamp -Value $LastLogonTimestamp -ErrorAction SilentlyContinue
	
			$CurrentDate = Get-Date 
			$Diff = New-TimeSpan -Start $LastLogonTimestamp -End $CurrentDate
			$diffDays = $Diff.Days
			if (($diffDays -ge 21) -or ($diffDays.length -eq 0)) {
				Add-Member -InputObject $DeviceHealth -MemberType NoteProperty -Name DeviceStale -Value $True -ErrorAction SilentlyContinue
			} else {
				Add-Member -InputObject $DeviceHealth -MemberType NoteProperty -Name DeviceStale -Value $False -ErrorAction SilentlyContinue
			}

			# Check if device in Pending State
			$Cert = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($AADDevice.value.alternativeSecurityIds.key))
            $AltSec = $Cert -replace $cert[1]

            if (-not ($AltSec.StartsWith("X509:"))) {
                $devicePending=$true
            } else {
                $devicePending=$false
            }
			Add-Member -InputObject $DeviceHealth -MemberType NoteProperty -Name DevicePending -Value $devicePending -ErrorAction SilentlyContinue
        } else {
            # Device was not found
            Add-Member -InputObject $DeviceHealth -MemberType NoteProperty -Name DeviceExists -Value $False -ErrorAction SilentlyContinue
        }
	} catch {
        Write-Host ''
        Write-Host "Operation aborted. Unable to connect to Azure AD, please check you entered a correct credentials and you have the needed permissions" -ForegroundColor red
        Write-Host ''
        Write-Host ''
        Write-Host "Script completed successfully." -ForegroundColor Green
        Write-Host ''
        Write-Host ''
        exit
    }

	return $DeviceHealth
}


function Wait-OnDemandStop {
	$LogName = "Application"
	$Log = [System.Diagnostics.EventLog]$LogName
	$Action = {
		$entry = $event.SourceEventArgs.Entry
		if ($entry.EventId -eq 2 -and $entry.Source -eq "MDEClientAnalyzer")
		{
			Write-Host "Stop event was triggered!" -ForegroundColor Green
			Unregister-Event -SourceIdentifier MDEClientAnalyzer
			Remove-Job -Name MDEClientAnalyzer
		}
	}
	Register-ObjectEvent -InputObject $log -EventName EntryWritten -SourceIdentifier "MDEClientAnalyzer" -Action $Action | Out-Null
	$timeout = New-TimeSpan -Minutes $MinutesToRun
	$sw = [diagnostics.stopwatch]::StartNew()
	try {
		do {
			Wait-Event -SourceIdentifier MDEClientAnalyzer -Timeout 1
			[int]$rem = $timeout.TotalSeconds - $sw.elapsed.TotalSeconds
			Write-Host "Remaining seconds: " ([math]::Round($rem))
		} while ((Get-Job -Name MDEClientAnalyzer -ErrorAction SilentlyContinue) -xor ([int]$rem -lt 1))
	} finally {
		 Unregister-Event -SourceIdentifier MDEClientAnalyzer -ErrorAction SilentlyContinue
		 Remove-Job -Name MDEClientAnalyzer -ErrorAction SilentlyContinue
	}
}

function Create-OnDemandStopEvent {
	Write-host "Another non-interactive trace is already running... stopping log collection and exiting."
	Write-EventLog -LogName "Application" -Source "MDEClientAnalyzer" -EventID 2 -EntryType Information -Message "MDEClientAnalyzer is stopping a running log set" -Category 1
	[Environment]::Exit(1)
}

function Create-OnDemandStartEvent {
	Write-EventLog -LogName "Application" -Source "MDEClientAnalyzer" -EventID 1 -EntryType Information -Message "MDEClientAnalyzer is starting OnDemand traces" -Category 1	
}

#Main
CheckAuthenticodeSignature $MyInvocation.MyCommand.Path
[bool]$system = ([System.Security.Principal.WindowsIdentity]::GetCurrent().IsSystem)
[string]$context = ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
[string]$LoggedOnUsers = (Get-Process -Name "Explorer" -IncludeUserName -ErrorAction SilentlyContinue).UserName | Sort-Object UserName -Unique
if (!$system) {
	if ($LoggedOnUsers -contains $context) {
	# This means the user context running the script is also interactively logged on
	$InteractiveAdmin = $true
	}
}

$EULA = Join-Path $ToolsDir "EULA.ps1"
CheckAuthenticodeSignature $EULA
Import-module $EULA

if ($system -or $RemoteRun) {
	# Running in non-interactive mode. I.e. assume EULA accepted by admin who is initiating advanced data collection 
	$eulaAccepted = ShowEULAIfNeeded "MDEClientAnalyzer" 2
} else {
	$eulaAccepted = ShowEULAIfNeeded "MDEClientAnalyzer" 0
}

if ($eulaAccepted -ne "Yes") {
    write-error "MDEClientAnalyzer EULA Declined"
    [Environment]::Exit(1)
}
write-host "MDEClientAnalyzer EULA Accepted"

if ($PSMode -eq "ConstrainedLanguage") {
	Write-Warning "PowerShell is set with 'Constrained Language' mode hardening which can affect script execution and capabilities. To avoid issues while troubleshooting with the analyzer, please temporarly remove the ConstrainedLanguage mode in your policy."
	Write-Host "For more information, refer to: https://docs.microsoft.com/powershell/module/microsoft.powershell.core/about/about_language_modes"
	if (!($system -or $RemoteRun)) {
		Read-Host "Press ENTER to continue anyway..."
	}
}

New-EventLog –LogName Application –Source "MDEClientAnalyzer" -ErrorAction SilentlyContinue
[array]$RunningPS = Get-WmiObject Win32_Process | Where-Object {$_.name -eq 'powershell.exe'}
foreach ($PS in $RunningPS) {
	If ($PID -ne ($PS.ProcessId)) {
		$StringRunningPS = ([string]$PS.CommandLine).ToLower()
		if (($StringRunningPS).contains(" -r") -and (($StringRunningPS).contains("mdeclientanalyzer.ps1'"))) { 
			# This means we have a previous trace already kicked off and running, so signal to stop log collection and exit.
			Create-OnDemandStopEvent
		}
	} 
}

InitXmlLog
[string]$PSMode = ($ExecutionContext.SessionState.LanguageMode)
[int]$OSBuild = [system.environment]::OSVersion.Version.Build
[int]$MinorBuild = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\" -Value "UBR" )
[string]$OSEditionID = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Value EditionID
[string]$OSProductName = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Value ProductName
if (($OSProductName -like "Windows 10*") -And ($OSBuild -ge 22000)) {
	[string]$OSProductName = (Get-WMIObject win32_operatingsystem).Caption
}
[string]$OSEditionName = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Value InstallationType
[string]$IsOnboarded = Get-RegistryValue -Path "HKLM:\SOFTWARE\\Microsoft\Windows Advanced Threat Protection\Status" -Value OnboardingState 
[int]$PsMjVer = $PSVersionTable.PSVersion.Major
# Below is using WMI instead of $env:PROCESSOR_ARCHITECTURE to avoid getting the PS env instead of the actual OS archecture
[string]$arch = (Get-WmiObject -Class Win32_OperatingSystem).OSArchitecture
[string]$MDfWS = GetAddRemovePrograms (Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall) | Where-Object {$_.DisplayName -like "Microsoft Defender for *"}
[string]$LastSystemBootTime = (Get-WmiObject win32_operatingsystem | select @{LABEL='LastBootUpTime';EXPRESSION={$_.ConverttoDateTime($_.lastbootuptime)}}).LastBootUpTime

if ($arch -like "ARM*") {
	$ARM = $true
	$ARMcommand = "-ARM"
}

if (Get-Process WDATPLauncher -EA silentlycontinue) {
	$SignerInfo = ((Get-AuthenticodeSignature (Get-Process WDATPLauncher).Path).SignerCertificate).Subject
	if ($SignerInfo -like "*Microsoft Corporation*") {
		$ASM = $true
	}
}

# Storing HKU reg path for later use
New-PSDrive HKU Registry HKEY_USERS -ErrorAction SilentlyContinue | Out-Null

if (($OSBuild -le 7601) -And ($PsMjVer -le 2)) { 
	Write-Host -ForegroundColor Yellow "We recommend installing at least 'Windows Management Framework 3.0' (KB2506143) or later for optimal script results: `r`nhttps://www.microsoft.com/en-us/download/details.aspx?id=34595"
}

if ((Test-Path -Path $ToolsDir) -eq $False) {
	Write-Host -ForegroundColor Yellow "Missing 'Tools' directory. Exiting script."
	[Environment]::Exit(1)
}

# Delete previous output if exists
if (Test-Path $resultOutputDir) {
	Remove-Item -Recurse -Force $resultOutputDir -ErrorVariable FileInUse;
	while ($FileInUse) {
		Write-Warning "Please close any opened log files from previous MDEClientAnalyzer run and then try again."
		Read-Host "Press ENTER once you've closed all open files."
		Remove-Item -Recurse -Force $resultOutputDir -ErrorVariable FileInUse
	}
}
if (Test-Path $outputZipFile) {
	Remove-Item -Recurse -Force  $outputZipFile
}

#Check if Evens.Json File not exist
if (-not (Test-Path $ResourcesJson)) {
	Write-Error 'The Events.jsonfile does not exist' -ErrorAction Stop
}
CheckHashFile "$ResourcesJson" "8C193EA33E646DC55747148B674D7140535619FD3BA299EB0A80354AF59ED730" #Changed whenever new event is added to report
CheckHashFile "$RegionsJson" "B2C2D3F4A97B90B4C5ED5515BCC55F31E1F15FB3C73996D2FBF29945C77A6CF4"
$ResourcesOfEvents = (Get-Content $ResourcesJson -raw) | ConvertFrom-Json

# Create output folders
New-Item -ItemType directory -Path $resultOutputDir | Out-Null
NTFSSecurityAccess $resultOutputDir

New-Item -ItemType Directory -Path "$resultOutputDir\EventLogs" | out-Null
New-Item -ItemType Directory -Path "$resultOutputDir\SystemInfoLogs" | out-Null

#Store paths for MpCmdRun.exe usage
if (((Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" -Value ImagePath) -and ($OSBuild -ge 14393)) -or ($MDfWS)) {
	$MsMpEngPath = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" -Value ImagePath
	[System.IO.DirectoryInfo]$CurrentMpCmdPath = $MsMpEngPath -replace "MsMpEng.exe" -replace """"
	$MpCmdRunCommand = Join-Path $CurrentMpCmdPath "MpCmdRun.exe"
	$MpCmdResultPath = "$env:ProgramData\Microsoft\Windows Defender\Support"
}
elseif (Test-Path -path "$env:ProgramFiles\Microsoft Security Client\MpCmdRun.exe") {
	$CurrentMpCmdPath = "$env:ProgramFiles\Microsoft Security Client\"
	$MpCmdRunCommand = "$env:ProgramFiles\Microsoft Security Client\MpCmdRun.exe"
	$MpCmdResultPath = "$env:ProgramData\Microsoft\Microsoft Antimalware\Support"
}

Write-Report -section "general" -subsection "PSlanguageMode" -displayname "PowerShell Language mode: " -value $PSMode
Write-Report -section "general" -subsection "scriptVersion" -displayname "Script Version: " -value $ScriptVer
$ScriptRunTime = "{0:dd/MM/yyyy h:mm:ss tt zzz}" -f (get-date)
Write-Report -section "general" -subsection "scriptRunTime" -displayname "Script RunTime: " -value $ScriptRunTime 

Write-output "######################## device Info summary #############################" | Out-File $connectivityCheckFile -append
#if ((($OSBuild -ge 7601 -and $OSBuild -le 14393) -and ($OSProductName -notmatch 'Windows 10')) -and (($OSEditionID -match 'Enterprise') -or ($OSEditionID -match 'Pro') -or ($OSEditionID -match 'Ultimate') -or ($OSEditionID -match 'Server'))) {

if (!(Get-Service -Name Sense -ErrorAction SilentlyContinue)) {
	$OSPreviousVersion = $true
	$global:SenseVer=""
	Collect-RegValue
	CheckConnectivity -OSPreviousVersion $OSPreviousVersion -connectivityCheckFile $connectivityCheckFile -connectivityCheckUserFile $connectivityCheckUserFile
      
	if ($Global:tdhdll.Valid -and $Global:wintrustdll.Valid -and !($global:SSLProtocol)) {
		"OS Environment is  supported: " + [System.Environment]::OSVersion.VersionString | Out-File $connectivityCheckFile -append
	}
	else {
		"OS Environment is not  supported: " + [System.Environment]::OSVersion.VersionString + " More information below" | Out-File $connectivityCheckFile -append
	}

	if ($Global:connectivityresult -match "failed" ) {
		"Command and Control channel as System Account : Some of the MDE APIs failed , see details below" | Out-File $connectivityCheckFile -append
	}
	elseif (!$Global:connectivityresult) {
		"Command and Control channel as System Account: Not tested" | Out-File $connectivityCheckFile -append 
	}
	else {
		"Command and Control channel as System Account: Passed validation" | Out-File $connectivityCheckFile -append 
	}

	if ($Global:connectivityresultUser -match "failed" ) {
		"Command and Control channel as User Account : Some of the MDE APIs failed , see details below" | Out-File $connectivityCheckFile -append
	}
	elseif (!$Global:connectivityresultUser) {
		"Command and Control channel as User Account: Not tested" | Out-File $connectivityCheckFile -append 
	}
	else {
		"Command and Control channel as User Account: Passed validation" | Out-File $connectivityCheckFile -append 
	}

	if (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\services\HealthService\Parameters") {
		Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\services\HealthService\Parameters -recurse | Format-table -AutoSize | Out-File "$resultOutputDir\SystemInfoLogs\HealthServiceReg.txt"
		# Test if multiple MMA workspaces are configured
		$AgentCfg = New-Object -ComObject AgentConfigManager.MgmtSvcCfg
		$workspaces = $AgentCfg.GetCloudWorkspaces()
		if ($workspaces.Item(1)) {
			Write-output "`r`n############################ Multiple workspaces check ###############################" | Out-File $connectivityCheckFile -Append
			WriteReport 121001 @() @()
		}
	}
} 

if ((!$OSPreviousVersion) -or ($MDfWS)) {
	if ($IsOnboarded) {
		Collect-RegValue

		$SenseServiceStatus = (Get-Service -Name Sense).Status 
		$UTCServiceStatus = (Get-Service -Name DiagTrack).Status
		$DefenderServiceStatus = (Get-Service -Name WinDefend).Status
        [string]$DefenderAVProxy = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Value ProxyServer

		Write-Report -section "EDRCompInfo" -subsection "SenseServiceStatus" -displayname "Sense service Status" -value $SenseServiceStatus
		Write-Report -section "EDRCompInfo" -subsection "UTCServiceStatus" -displayname "DiagTrack (UTC) Service Status" -value $UTCServiceStatus
		Write-Report -section "AVCompInfo" -subsection "DefenderServiceStatus" -displayname "Defender AV Service Status" -value $DefenderServiceStatus
		if (Get-Service -name wscsvc -ErrorAction SilentlyContinue) {
			$WindowsSecurityCenter = (Get-Service -Name wscsvc).Status
			Write-Report -section "AVCompInfo" -subsection "WindowsSecurityCenter" -displayname "Windows Security Center Service Status" -value $WindowsSecurityCenter
		}
		if (Get-Service -name SecurityHealthService -ErrorAction SilentlyContinue) {
			$SecurityHealthService = (Get-Service -Name SecurityHealthService).Status
			Write-Report -section "AVCompInfo" -subsection "SecurityHealthService" -displayname "Windows Security Health Service Status" -value $SecurityHealthService
		}

		if (($OSEditionName -notlike "*core") -and (!$MDfWS)) {
			#"Microsoft Account Sign-in Assistant service start type is: " + (Get-Service -Name wlidsvc).StartType | Out-File $connectivityCheckFile -append
			$WLIDServiceStartType = (Get-Service -Name wlidsvc -ErrorAction SilentlyContinue).StartType
			Write-Report -section "EDRCompInfo" -subsection "WLIDServiceStartType" -displayname "Microsoft Account Sign-in Assistant Start Type" -value $WLIDServiceStartType
		}
		If ($DefenderServiceStatus -eq "Running") {
            if ($DefenderAVProxy) {
                Write-Report -section "AVCompInfo" -subsection "DefenderAVProxy" -displayname "Defender AV proxy configuration" -value $DefenderAVProxy
            }
			if (($OSEditionID -match 'Server') -and (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender" -Value "ForcePassiveMode")) {
				$AVPassiveMode = $true
				Write-Report -section "AVCompInfo" -subsection "DefenderState" -displayname "Defender AV mode" -value "Passive (Forced)"
			}
			elseif (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender" -Value "PassiveMode") {
				$AVPassiveMode = $true
				Write-Report -section "AVCompInfo" -subsection "DefenderState" -displayname "Defender AV mode" -value "Passive"
			}
			else {
				Write-Report -section "AVCompInfo" -subsection "DefenderState" -displayname "Defender AV mode" -value "Active" -alert "None"
			}		
		}

		if (!$ASM) {
			if ($OSBuild -eq 14393) {
				$LastCYBERConnected = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\SevilleSettings" -Value LastNormalUploadTime)
				$LastCYBERRTConnected = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\SevilleSettings" -Value LastRealTimeUploadTime)
				$LastInvalidHTTPcode = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\HeartBeats\Seville" -Value LastInvalidHttpCode)
				Dump-ConnectionStatus 
			}
			elseif ($OSBuild -le 17134) {
				$LastCYBERConnected = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\Tenants\P-WDATP" -Value LastNormalUploadTime)
				$LastCYBERRTConnected = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\Tenants\P-WDATP" -Value LastRealTimeUploadTime)
				$LastInvalidHTTPcode = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\HeartBeats\Seville" -Value LastInvalidHttpCode)
				Dump-ConnectionStatus
			}
			elseif ($OSBuild -ge 17763) {
				$LastCYBERConnected = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\TelLib" -Value LastSuccessfulNormalUploadTime)
				$LastCYBERRTConnected = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\TelLib" -Value LastSuccessfulRealtimeUploadTime)
				$LastInvalidHTTPcode = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\TelLib\HeartBeats\Seville" -Value LastInvalidHttpCode)
				Dump-ConnectionStatus
			}
		}

		if ((Get-Process -Name MsSense -ErrorAction SilentlyContinue) -And ($OSProductName -notlike "*LTSB")) {
			Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\48A68F11-7A16-4180-B32C-7F974C7BD783" -ErrorAction SilentlyContinue -ErrorVariable AFERR
			[string]$StateReg = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection" -Value "7DC0B629-D7F6-4DB3-9BF7-64D5AAF50F1A")
			if (!$StateReg) {
				[string]$StateRegHardended = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\48A68F11-7A16-4180-B32C-7F974C7BD783" -Value "7DC0B629-D7F6-4DB3-9BF7-64D5AAF50F1A" -ErrorAction "SilentlyContinue")
			}
			if ($StateReg) {
				Write-Report -section "EDRCompInfo" -subsection "AFState" -displayname "Anti-Spoofing capability deployed" -value "YES"
				if ("66748D4C-F662-482E-8EAE-F8D73CD9AFED" -eq ([string]$StateReg)) {
					[string]$SenseId = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection" -Value "SenseId")
					if ((Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection" -Value "C9D38BBB-E9DD-4B27-8E6F-7DE97E68DAB9") -eq ([string]$SenseId)) {
						WriteReport 120037 @() @()
					# VDI has special Anti-Spoofing handling in cloud so only throw this warning if not running a VDI machine
					} elseif (!$IsVDI) {
						WriteReport 121036 @() @()
						$UnstableAntiSpoof = $true
					}
				} else {
					WriteReport 121040 @() @()
				}
			} elseif (([string]$AFERR) -and (!$StateReg)) {
				if ([string]$AFERR -NotLike "Requested registry access is not allowed.") {
					Write-Report -section "EDRCompInfo" -subsection "AFState" -displayname "Anti-Spoofing capability deployed" -value "NO"
					WriteReport 121035 @() @()
				}
			} if ($StateRegHardended) {
				Write-Report -section "EDRCompInfo" -subsection "AFState" -displayname "Anti-Spoofing capability deployed" -value "YES"
				if ("66748D4C-F662-482E-8EAE-F8D73CD9AFED" -eq ([string]$StateRegHardended)) {
					[string]$SenseId = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection" -Value "SenseId")
					if ((Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\48A68F11-7A16-4180-B32C-7F974C7BD783" -Value "C9D38BBB-E9DD-4B27-8E6F-7DE97E68DAB9") -eq ([string]$SenseId)) {
						WriteReport 120037 @() @()
					# VDI has special Anti-Spoofing handling in cloud so only throw this warning if not running a VDI machine
					} elseif (!$IsVDI) {
						WriteReport 121036 @() @()
						$UnstableAntiSpoof = $true
					}
				} else {
					WriteReport 121040 @() @()
				}
			}
		}
		# Test for events indicating expired OrgID in Sense event logs
		Write-output "`r`n############################ OrgID error check ###############################" | Out-File $connectivityCheckFile -Append
		$OrgId = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status" -Value "OrgID" )
		$EventError = (Get-MatchingEvent Microsoft-Windows-SENSE 67 "400")
		if (!$EventError) {
			$EventError = (Get-MatchingEvent Microsoft-Windows-SENSE 5 "400")
		}
		$EventOk = (Get-MatchingEvent Microsoft-Windows-SENSE 50 "*10.*")
		if (!$EventError) {
			"Based on SENSE log, no OrgId mismatch errors were found in events" | Out-File $connectivityCheckFile -Append
		} 		
		if (($EventOk) -and ($EventError)) {
			if ((Get-Date $EventOk.TimeCreated) -gt (Get-Date $EventError.TimeCreated)) {
				"Based on SENSE log, the device is linked to an active Organization ID: $orgID`r`n" | Out-File $connectivityCheckFile -Append
			} 
		}
		# Ignore the error if the AntiSpoofing component is unstable as it can also cause error 400
		elseif (($EventError) -and (!$UnstableAntiSpoof)) {
			Write-output "Event Log error information:" | Out-File $connectivityCheckFile -Append
			$EventError | Format-Table -Wrap | Out-File $connectivityCheckFile -Append
			WriteReport 122005 @(, @($OrgId)) @()
		}
	} 

	# Dump Registry OnboardingInfo if exists
	$RegOnboardingInfo = Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\" -Value OnboardingInfo 
	$RegOnboardedInfo = Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\" -Value OnboardedInfo 
	if (($RegOnboardingInfo -eq $False) -or ($RegOnboardingInfo -eq $null)) {
		Get-deviceInfo
		"`r`Note: OnboardingInfo could not be found in the registry. This can be expected if device was offboarded or onboarding was not yet executed." | Out-File $connectivityCheckFile -Append
	} else {
		($RegOnboardingInfo | ConvertFrom-Json).body | Out-File "$resultOutputDir\SystemInfoLogs\RegOnboardingInfoPolicy.Json"
		($RegOnboardedInfo | ConvertFrom-Json).body | Out-File "$resultOutputDir\SystemInfoLogs\RegOnboardedInfoCurrent.Json"
	}
	CheckConnectivity -OSPreviousVersion $OSPreviousVersion -connectivityCheckFile $connectivityCheckFile -connectivityCheckUserFile $connectivityCheckUserFile
}

# Check if MDE for down-level server is installed
if (($OSEditionID -match 'Server') -and ($OSBuild -ge 7601 -and $OSBuild -le 14393)) {
	if ($MDfWS) {
		Write-Report -section "EDRCompInfo" -subsection "MDfWSState" -displayname "Unified agent for downlevel servers installed" -value "YES" 
		[version]$minVer = "10.8049.22439.1084"
		if ([version]$Global:SenseVer -lt [version]$minVer) {
			WriteReport 122038 @() @()
		}
	} else {
		Write-Report -section "EDRCompInfo" -subsection "MDfWSState" -displayname "Unified agent for downlevel servers installed" -value "NO"
		WriteReport 121020 @() @()
	}
}

If ($CurrentMpCmdPath) {
	    $AVSignatureVersion = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Signature Updates" -Value "AVSignatureVersion" ) 
		$AVEngineVersion = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Signature Updates" -Value "EngineVersion" ) 
			
		#Check AV component versions to ensure they are up-to-date and report to Result
		$FilePathEPPversions = Join-Path $ToolsDir "EPPversions.xml"
		CheckHashFile $FilePathEPPversions "AE545C7A4F03071646E73B6A783F18F524B1F3F7BF8797835B73337C8FDCB368"
		$CheckAV = Join-Path $ToolsDir "MDE.psm1"
		CheckAuthenticodeSignature $CheckAV
		Import-Module $CheckAV
		$CheckAVHelper = Join-Path $ToolsDir "MDEHelper.psd1"
		CheckAuthenticodeSignature $CheckAVHelper
		Import-Module $CheckAVHelper			
		$WebRequestAV = [net.WebRequest]::Create("https://www.microsoft.com/security/encyclopedia/adlpackages.aspx?action=info")
		try {
			$WebRequestAV.GetResponse().StatusCode
		}
		catch [System.Net.WebException] {
			$ErrorMessage = $Error[0].Exception.ErrorRecord.Exception.Message;
		}
		$WebRequestAV.Close
		if ($CurrentMpCmdPath.Name -like "*-*") {
				[string]$Platform = $CurrentMpCmdPath.Name.split('-')[0]
		}
		$MoCAMPAlert = "None"; $EngineAlert = "None"; $SigsAlert = "None"; 
		if ($ErrorMessage -eq $null) {
			if (checkeppversion -component MoCAMP -version $Platform) {
				$MoCAMPAlert = "High"
				WriteReport 122010 @() @()
			} 
			if (checkeppversion -component Engine -version $AVEngineVersion) {
				$EngineAlert = "High"
				WriteReport 122011 @() @()
			} 
			if (checkeppversion -component Sigs -version $AVSignatureVersion) {
				$SigsAlert = "Medium"
				WriteReport 121012 @() @()
			} 
		} else {
			[XML]$EPPversions = Get-Content $FilePathEPPversions
			#Option to check the AV state using the included EPPversions.xml ($FilePathEPPversions)
			if (checkeppversion -component MoCAMP -version $Platform -xml $EPPversions) {
				$MoCAMPAlert = "High"
				WriteReport 122010 @() @()
			} 
			if (checkeppversion -component Engine -version $AVEngineVersion -xml $EPPversions) {
				$EngineAlert = "High"
				WriteReport 122011 @() @()
			} 
			if (checkeppversion -component Sigs -version $AVSignatureVersion -xml $EPPversions) {
				$SigsAlert = "Medium"
				WriteReport 121012 @() @()
			} 
		}	
		Write-Report -section "AVCompInfo" -subsection "AVPlatformVersion" -displayname "Defender AV Platform Version" -value $CurrentMpCmdPath.Name -alert $MoCAMPAlert
		Write-Report -section "AVCompInfo" -subsection "AVSignatureVersion" -displayname "Defender AV Security Intelligence Version" -value $AVSignatureVersion -alert $SigsAlert
		Write-Report -section "AVCompInfo" -subsection "AVEngineVersion" -displayname "Defender AV engine Version" -value $AVEngineVersion -alert $EngineAlert 
}

if ((($OSBuild -ge 7601 -and $OSBuild -le 14393) -and ($OSProductName -notmatch 'Windows 10')) -and (($OSEditionID -match 'Enterprise') -or ($OSEditionID -match 'Pro') -or ($OSEditionID -match 'Ultimate') -or ($OSEditionID -match 'Server'))) {
	"`r`n###################### OMS validation details  ###########################" | Out-File $connectivityCheckFile -append
	if ($Global:TestOMSResult -match "Connection failed" -or $Global:TestOMSResult -match "Blocked Host") {
		"OMS channel: Some of the OMS APIs failed , see details below" | Out-File $connectivityCheckFile -append
	}
 elseif (!$Global:TestOMSResult) {
		"OMS channel: Not tested" | Out-File $connectivityCheckFile -append 
	}
 elseif (!$MDfWS) {
		"OMS channel: Passed validation" | Out-File $connectivityCheckFile -append 
		"Service Microsoft Monitoring Agent is " + (Get-Service -Name HealthService -ErrorAction SilentlyContinue).Status | Out-File $connectivityCheckFile -append
		"Health Service DLL version is: " + $Global:healthservicedll.version | Out-File $connectivityCheckFile -append
		If (!$Global:healthservicedll.Valid) {
			"`n" | Out-File $connectivityCheckFile -append
			WriteReport 122002 @(, @($Global:healthservicedll.Message)) @()
		}
	} 
	"`r`n###################### OS validation details  ###########################" | Out-File $connectivityCheckFile -append
	$Global:tdhdll.Message  | Out-File $connectivityCheckFile -append
	$Global:wintrustdll.Message  | Out-File $connectivityCheckFile -append
	$global:SSLProtocol | Out-File $connectivityCheckFile -append
	Write-output "##########################################################################`n" | Out-File $connectivityCheckFile -append  
	"######## Connectivity details for Command and Control  validation  #######" | Out-File $connectivityCheckFile -append
	$connectivityresult | Out-File $connectivityCheckFile -append
	Write-output "##########################################################################`n" | Out-File $connectivityCheckFile -append  
	"################# Connectivity details for OMS  validation  #########" | Out-File $connectivityCheckFile -append
	$Global:TestOMSResult | Out-File $connectivityCheckFile -append
	Write-output "##########################################################################`n" | Out-File $connectivityCheckFile -append  
}

# Checks for MDE Device Configuration
if ((($osbuild -gt 9600) -or (($osbuild -eq 9600) -and ($OSEditionID -match 'Server'))) -and ($IsOnboarded)) {
	$SenseCMConfig = Get-SenseCMInfo

	Write-output "`r`n################# Device Registration and Enrollment ##################" | Out-File $connectivityCheckFile -Append
	# Check SenseCM enrollment Status
	if ($SenseCMConfig.EnrollmentStatusId) {
		$EnrollmentStatusAlert = ""
		If ($SenseCMConfig.EnrollmentStatusReportId) {
			$EnrollmentStatusAlert = "High"
			WriteReport $SenseCMConfig.EnrollmentStatusReportId @() @()
		} 
		If ($SenseCMConfig.EnrollmentStatusId -eq "1") { $EnrollmentStatusAlert = "None" }
		Write-Report -section "MDEDevConfig" -subsection "SenseCMEnrollmentStatus" -displayname "Enrollment Status" -value $SenseCMConfig.EnrollmentStatusText -alert $EnrollmentStatusAlert
		if ($SenseCMConfig.AADDeviceId) {
			Write-Report -section "MDEDevConfig" -subsection "IntuneDeviceID" -displayname "Intune Device ID" -value $SenseCMConfig.IntuneDeviceID
			Write-Report -section "MDEDevConfig" -subsection "AADDeviceID" -displayname "Azure AD Device ID" -value $SenseCMConfig.AADDeviceId 
			Write-Report -section "MDEDevConfig" -subsection "AADTenantId" -displayname "Azure AD Tenant ID" -value $SenseCMConfig.TenantId 
		}
	}

	if ($env:userdnsdomain) {
		Write-Report -section "MDEDevConfig" -subsection "DomainJoined" -displayname "Domain Joined" -value "YES"
		$DomainJoined = $True
	} else {
		Write-Report -section "MDEDevConfig" -subsection "DomainJoined" -displayname "Domain Joined" -value "NO"
		$DomainJoined = $False
	}
	# Collect information about up-level OS
	if ($osbuild -gt "9600") {
		# Check if the October hotfix is installed for supported Windows 10 versions and Windows Server 2019
		if ((($osbuild -eq "19041") -and ([int]$MinorBuild -lt 1320)) -or (($osbuild -eq "19042") -and ([int]$MinorBuild -lt 1320)) -or (($osbuild -eq "19043") -and ([int]$MinorBuild -lt 1320)) -or (($osbuild -eq "17763") -and ([int]$MinorBuild -lt 2268))) {
			WriteReport 111021 @(, @("$OSBuild.$MinorBuild")) @()
		} 

		# Collect Information from DSREGCMD 
		$DSRegState = Get-DsRegStatus		
		# Write-Report -section "MDEDevConfig" -subsection "DomainJoined" -displayname "Domain Joined" -value $DomainJoined
		Write-Report -section "MDEDevConfig" -subsection "AzureADJoined" -displayname "Azure AD Joined" -value $DSRegState.DeviceState.AzureAdJoined
		Write-Report -section "MDEDevConfig" -subsection "WorkplaceJoined" -displayname "Workplace Joined" -value $DSRegState.UserState.WorkplaceJoined
		if ((!$SenseCMConfig.AADDeviceId) -and ($DSRegState.DeviceDetails.DeviceID)) {
			Write-Report -section "MDEDevConfig" -subsection "AADDeviceID" -displayname "Azure AD Device ID" -value $DSRegState.DeviceDetails.DeviceID 
			
			$MDMEnrollmentState = Get-MDMEnrollmentStatus
			Write-Report -section "MDEDevConfig" -subsection "MDMEnrollmentState" -displayname "MDM Enrollment state" -value $MDMEnrollmentState.EnrollmentTypeText
		}
	}

	if ($DomainJoined) {
		$SCPConfiguration = Get-SCPConfiguration
		if ($SCPConfiguration.ResultID -eq "") {
			Write-Report -section "MDEDevConfig" -subsection "SCPClientSide" -displayname "SCP Configuration Type" -value $SCPConfiguration.ConfigType
			Write-Report -section "MDEDevConfig" -subsection "SCPTenantName" -displayname "SCP Tenant Name" -value $SCPConfiguration.TenantName
			Write-Report -section "MDEDevConfig" -subsection "SCPTenantID" -displayname "SCP Tenant ID" -value $SCPConfiguration.TenantId
				
			if ((!$SenseCMConfig.TenantId) -xor (!$SCPConfiguration.TenantId)) {
					WriteReport 120021 @() @()
			} elseif ((((!$SenseCMConfig.TenantId) -and (!$SCPConfiguration.TenantId)) -and ($SenseCMConfig.TenantId -notmatch $SCPConfiguration.TenantId)) -or ($SenseCMConfig.EnrollmentStatusId -eq 15)) {
				WriteReport 121022 @() @()
			}
		} elseif (($SCPConfiguration.ResultID -eq 121017) -or ($SenseCMConfig.EnrollmentStatusId -eq 15)) {
				WriteReport $SCPConfiguration.ResultID @(, @($SCPConfiguration.TenantName)) @()
			} else {
				WriteReport $SCPConfiguration.ResultID  @() @()
			}
	}
}

if ((!$OSPreviousVersion) -or ($MDfWS)) {
	Write-output "`r`n################# Defender AntiVirus cloud service check ##################" | Out-File $connectivityCheckFile -Append
	if ($MpCmdRunCommand) {
		CheckAuthenticodeSignature $MpCmdRunCommand
		$MAPSCheck = &$MpCmdRunCommand -ValidateMapsConnection
		$MAPSErr = $MAPSCheck | Select-String -pattern "ValidateMapsConnection failed"
		if ($MAPSErr) { 
			WriteReport 131007 @(, @($MAPSErr)) @()
		}
		else {
			$MAPSOK = $MAPSCheck | Select-String -pattern "ValidateMapsConnection successfully"
			if ($MAPSOK) {
				WriteReport 130011 @() @()
			}
		}
	}
}

# Dump DLP related policy information from registry
if (($DlpT) -or ($AppCompatC) -or ($DlpQ) -or ($wprpTraceH)) {
	if ((!$OSPreviousVersion) -and ($OSBuild -ge 17763)) {
		New-Item -ItemType Directory -Path "$resultOutputDir\DLP" | out-Null
		<# 
		# The below captures the local AD user UPN. We should also fetch UPN in case of Azure AD
		if ($InteractiveAdmin) {
			[string]$UserUPN = ([ADSI]"LDAP://<SID=$([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)>").UserPrincipalName
			$UserUPN | Out-File "$resultOutputDir\DLP\dlpPolicy.txt" -Append
		}
		#>
		if (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection" -Value dlpPolicy) {
			ShowDlpPolicy dlpPolicy
			ShowDlpPolicy dlpSensitiveInfoTypesPolicy
			if (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection" -Value dlpActionsOverridePolicy) {
				ShowDlpPolicy dlpActionsOverridePolicy
			}
			if (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection" -Value dlpWebSitesPolicy) {
				ShowDlpPolicy dlpWebSitesPolicy
			}
			$DLPlogs = Get-Item "$env:SystemDrive\DLPDiagnoseLogs\*.log" -ErrorAction SilentlyContinue
			if ($DLPlogs) {
				Move-Item -Path $DLPlogs -Destination "$resultOutputDir\DLP\"
			}
		}
		else {
			Write-output "No DLP polices found in the registry of this device" | Out-File "$resultOutputDir\DLP\NoDlp.txt"
		}
	}
}

# Dump installed hotfix list via WMI call
$Computer = "LocalHost"
$Namespace = "root\CIMV2"
$InstalledUpdates = Get-WmiObject -class Win32_QuickFixEngineering -computername $Computer -namespace $Namespace
$InstalledUpdates | Out-File "$resultOutputDir\SystemInfoLogs\InstalledUpdates.txt"

<#Collect advanced traces if flagged
1. Start timer
2. Call the relevant function to start traces for various scenarios
3. When timer expires or manually stopped call the functions to stop traces for various scenarios
4. Gather logs common to all scenarios and finish
#>

if ($DlpQ -or $DlpT) {
	$DLPHealthCheck = Join-Path $ToolsDir "DLPDiagnose.ps1"
	CheckAuthenticodeSignature $DLPHealthCheck
	Check-Command-verified "powershell.exe"
	&Powershell.exe "$DLPHealthCheck"
}

if ($wprpTraceL -or $wprpTraceH -or $AppCompatC -or $NetTraceI -or $WDPerfTraceA -or $WDVerboseTraceV -or $DlpT) {
	$AdvancedFlag = $True
	Start-PSRRecording
	$WPtState = Test-WptState
	$MinutesToRun = Get-MinutesValue
	Start-Wpr
	Start-PerformanceTrace
	Start-AppCompatTrace
	Start-MDAVTrace
	Start-NetTrace
	StartTimer
	Stop-Wpr
	Stop-PerformanceTrace
	Stop-AppCompatTrace
	Stop-MDAVTrace
	Stop-NetTrace
	Get-DLPEA
	Get-Log
	Stop-PSRRecording
}

elseif ($BootTraceB) {
	$AdvancedFlag = $True
	Set-BootTrace
}

if ($CrashDumpD) {
	Get-CrashDump
}

if ($FullCrashDumpZ) {
	Set-CrashOnCtrlScroll
	Set-FullCrashDump
	Write-Host -BackgroundColor Red -ForegroundColor Yellow "Please reboot the device for the change in settings to apply" 
	Write-Host -ForegroundColor Green "To force the system to crash for memory dump collection, hold down the RIGHT CTRL key while pressing the SCROLL LOCK key twice"
	Write-Host "Note: This is not expected to work during Remote Desktop Protocol (RDP). For RDP please use the script with -k parameter instead"
}

if ($notmyfault) {
	Set-FullCrashDump
	if (!$RemoteRun) {
		[string]$notmyfault = (Read-Host "Type 'crashnow' and press ENTER to crash the device and create a full device dump now")
	}
	if (($notmyfault -eq "crashnow") -or ($RemoteRun)) {
		if ([Environment]::Is64BitOperatingSystem) {
			$NotMyFaultCommand = Join-Path $ToolsDir "NotMyFaultc64.exe"
		}
		else {
			$NotMyFaultCommand = Join-Path $ToolsDir "NotMyFaultc.exe"
		}
		CheckAuthenticodeSignature $NotMyFaultCommand
		& $NotMyFaultCommand /accepteula /Crash 1
	}
}

if (Test-Path -Path  $env:SystemRoot\System32\'Winevt\Logs\Operations Manager.evtx') {
	Copy-Item -path $env:SystemRoot\System32\'Winevt\Logs\Operations Manager.evtx' -Destination $resultOutputDir\EventLogs\OperationsManager.evtx
}

if (Test-Path -Path  $env:SystemRoot\System32\'Winevt\Logs\OMS Gateway Log.evtx') {
	Copy-Item -path $env:SystemRoot\System32\'Winevt\Logs\OMS Gateway Log.evtx' -Destination $resultOutputDir\EventLogs\OMSGatewayLog.evtx
}

if (test-path -Path $env:SystemRoot\System32\'Winevt\Logs\Microsoft-Windows-UniversalTelemetryClient%4Operational.evtx') {
	Copy-Item -path $env:SystemRoot\System32\Winevt\Logs\Microsoft-Windows-UniversalTelemetryClient%4Operational.evtx -Destination $resultOutputDir\EventLogs\utc.evtx
}

if (Test-Path -Path $env:SystemRoot\System32\'Winevt\Logs\Microsoft-Windows-SENSE%4Operational.evtx') {
	Copy-Item -path $env:SystemRoot\System32\Winevt\Logs\Microsoft-Windows-SENSE%4Operational.evtx -Destination $resultOutputDir\EventLogs\sense.evtx
	Copy-Item -path $env:SystemRoot\System32\Winevt\Logs\Microsoft-Windows-SenseIR%4Operational.evtx -Destination $resultOutputDir\EventLogs\senseIR.evtx -ErrorAction SilentlyContinue
}


# Test for ASR rule blocking PsExec
if ((!$OSPreviousVersion) -and (!$AVPassiveMode)) {
	TestASRRules    
}

# Check if automatic update of Trusted Root Certificates is blocked
$AuthRootLocal = get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\SystemCertificates\AuthRoot" -ErrorAction SilentlyContinue
$AuthRootGPO = get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot" -ErrorAction SilentlyContinue
if (($AuthRootLocal.DisableRootAutoUpdate -eq "1") -or ($AuthRootGPO.DisableRootAutoUpdate -eq "1")) {
	Write-output "`r`n######################## Auth Root Policies #########################" | Out-File $connectivityCheckFile -Append
	WriteReport 130009 @(@($AuthRootLocal), @($AuthRootGPO)) @()
	if ($OSPreviousVersion) {
		$EventError = Get-MatchingEvent HealthService 2132 "12175L"
	}
 else {
		$EventError = Get-MatchingEvent Microsoft-Windows-SENSE 5 "12175"
	}
	if ($EventError) {
		WriteReport 132012 @() @()
		$EventError | Format-Table -Wrap | Out-File $connectivityCheckFile -Append
	} 
}
$TelemetryProxyServer = Get-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Value "TelemetryProxyServer"
if (!$TelemetryProxyServer) {
	"############## Connectivity Check for ctldl.windowsupdate.com #############" | Out-File $connectivityCheckFile -append
	$urlctldl = "http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/pinrulesstl.cab"
	$webRequest = [net.WebRequest]::Create("$urlctldl")
	try {
		"StatusCode for " + $urlctldl + " IS : " + $webRequest.GetResponse().StatusCode | Out-File $connectivityCheckFile -append
	}
	catch [System.Net.WebException] {
		$ErrorMessage = $Error[0].Exception.ErrorRecord.Exception.Message;
		"Exception occurred for " + $urlctldl + " :" + $ErrorMessage | Out-File $connectivityCheckFile -append
		$Error[0].Exception.InnerException.Response | Out-File $connectivityCheckFile -append		
		WriteReport 131003 @() @()
	}
	$webRequest.Close
}

"############## CertSigner Results #############" | Out-File $CertSignerResults
$RootAutoUpdateDisabled = (($AuthRootLocal.DisableRootAutoUpdate -eq "1") -or ($AuthRootGPO.DisableRootAutoUpdate -eq "1"))
CheckExpirationCertUtil $RootAutoUpdateDisabled "authroot" "$ToolsDir\MsPublicRootCA.cer"
CheckExpirationCertUtil $RootAutoUpdateDisabled "disallowed"


# Check if only domain based trusted publishers are allowed
$AuthenticodeFlagsLocal = get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\SystemCertificates\TrustedPublisher\Safer" -ErrorAction SilentlyContinue
$AuthenticodeFlagsGPO = get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\TrustedPublisher\Safer" -ErrorAction SilentlyContinue
if (($AuthenticodeFlagsLocal.AuthenticodeFlags -eq "2") -or ($AuthenticodeFlagsGPO.AuthenticodeFlags -eq "2")) {
	Write-output "`r`n######################## Trusted Publishers Policy #########################" | Out-File $connectivityCheckFile -Append
	WriteReport 121009 @() @(@($AuthenticodeFlagsLocal), @($AuthenticodeFlagsGPO))
}

# Validate certificate revocation
# public .cer file was fetched from the https://winatp-gw-cus.microsoft.com/test this needs to be updated if certificate changes
if (!$OSPreviousVersion) {
	"`r`n##################### certificate validation check ########################" | Out-File $connectivityCheckFile -Append	
	$certutilcommand = Join-Path $ToolsDir "PsExec.exe"
	if (test-Path -path $certutilcommand) {
		CheckAuthenticodeSignature $certutilcommand
	}
	if (!$system) {
		Check-Command-verified "certutil.exe"
		&$certutilcommand -accepteula -s -nobanner certutil.exe -verify -urlfetch "$ToolsDir\winatp.cer" 2>> $connectivityCheckFile | Out-File $CertResults
	}
 elseif ($system) {
		Check-Command-verified "certutil.exe"
		&certutil.exe -verify -urlfetch "$ToolsDir\winatp.cer" | Out-File $CertResults
	}
	$Certlog = (Get-Content $CertResults)

	if (!$Certlog) {
		WriteReport 131004 @() @()
	}
 else {
		if (($Certlog -like "*Element.dwErrorStatus*") -or ($Certlog -like "*0x8007*")) {
			if ((($osbuild -eq "17763") -and ([int]$MinorBuild -lt 1911)) -or (($osbuild -eq "18363") -and ([int]$MinorBuild -lt 1411)) -or (($osbuild -eq "19041") -and ([int]$MinorBuild -lt 844)) -or (($osbuild -eq "19042") -and ([int]$MinorBuild -lt 964))) {
				WriteReport 131005 @() @(, @($CertResults))
			} 
		}
		else {
			WriteReport 130010 @() @()
		}
	}
}

Write-Host "Evaluating sensor condition..."
"########################### PROXY SETTINGS ################################" | Out-File $connectivityCheckFile -append
CheckProxySettings
Check-Command-verified "netsh.exe"
[array]$netshproxyoutput = (netsh.exe winhttp show proxy)
$netshproxyoutput | Out-File $connectivityCheckFile -append
if ($netshproxyoutput[3]) {
	Write-Report -section "devInfo" -subsection "SystemWideProxy" -displayname "System-wide WinHTTP proxy" -value $netshproxyoutput[3]
}
$ConOutput = (Get-Content $connectivityCheckFile)
[string]$SenseProxyOutput = ($ConOutput | Select-String -pattern "Proxy config: Method")
if ($SenseProxyOutput) {
	Write-Report -section "EDRCompInfo" -subsection "SenseProxyConfig" -displayname "Sense service discovered proxy" -value $SenseProxyOutput
}

# Check if device was onboarded using VDI script and dump relevant information
If (Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\DeviceTagging" -Value "VDI") {
	$IsVDI = $true
	Write-output "`r`n######################## VDI Information #########################" | Out-File $connectivityCheckFile -Append
	$StartupFolder = (get-ChildItem -Recurse -path $env:SystemRoot\system32\GroupPolicy\Machine\Scripts\Startup) 
	WriteReport 110003 @() @(, @($StartupFolder))
}

If (!$OSPreviousVersion) {
	# Test for DiagTrack listener on RS4 and earlier Win10 builds or SenseOms for Down-level OS, and export network proxy Registry settings
	Write-output "`r`n#################### Data Collection Registry setting #####################" | Out-File $connectivityCheckFile -Append

	$DiagTrackSvcStartType = (get-service -name diagtrack).StartType 
	If ($DiagTrackSvcStartType -eq "Disabled") {
		WriteReport 141001 @() @()
	}
	Get-Item HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection -ErrorAction SilentlyContinue | Out-File $connectivityCheckFile -Append
}
if ((!$OSPreviousVersion) -and ($buildNumber -le "17134") -and ($OSEditionName -eq "Client")) {
	Write-output "`r`n######################## DiagTrack Listener check #########################" | Out-File $connectivityCheckFile -Append
	Check-Command-verified "logman.exe"
	$DiagTrackListener = &logman Diagtrack-Seville-Listener -ets
	$DiagTrackListener > "$resultOutputDir\SystemInfoLogs\DiagTrackListener.txt"
	$SevilleProv = $DiagTrackListener | Select-String "CB2FF72D-D4E4-585D-33F9-F3A395C40BE7"
	if ($SevilleProv -eq $null) {
		WriteReport 141002 @() @()
	}
	else {
		WriteReport 140004 @() @()
	}	
}
elseif (($OSPreviousVersion) -and (!$ASM)) {
	Write-output "`r`n######################## SenseOms Listener check #########################" | Out-File $connectivityCheckFile -Append
	Check-Command-verified "logman.exe"
	$SenseOmsListener = &logman SenseOms -ets
	$SenseOmsListener > "$resultOutputDir\SystemInfoLogs\SenseOmsListener.txt"
	$OmsProv = $SenseOmsListener | Select-String "CB2FF72D-D4E4-585D-33F9-F3A395C40BE7"
	if ($OmsProv -eq $null) {
		WriteReport 141003 @() @()
	}
	else {
		WriteReport 140006 @() @()
	}	
}

if (!$OSPreviousVersion) {
	"################ Connectivity Check for Live Response URL ################" | Out-File $connectivityCheckFile -append
	$TestLR1 = TelnetTest "global.notify.windows.com" 443
	$TestLR2 = TelnetTest "client.wns.windows.com" 443
	$TestLR1 | Out-File $connectivityCheckFile -append
	$TestLR2 | Out-File $connectivityCheckFile -append
	# the abvoe test does not support proxy configuration as-is
	#if (($TestLR1 -notlike "Successfully connected*") -Or ($TestLR2 -notlike "Successfully connected*")) {
	#	Write-ReportEvent -section "events" -severity "Warning" -check "LRcheckFail" -id XXXXX -checkresult ( `
	#	"Failed to reach Windows Notification Service URLs required for Live Response.`r`n" `
	#	+ "Please ensure Live Response URLs are not blocked.`r`n" `
	#	+ "For more information, see: https://docs.microsoft.com/en-us/windows/uwp/design/shell/tiles-and-notifications/firewall-allowlist-config")
	#} elseif (($TestLR1 -like "Successfully connected*") -and ($TestLR2 -like "Successfully connected*")) {
	#	Write-ReportEvent -section "events" -severity "Informational" -check "LRcheckOK" -id XXXXX -checkresult ( `
	#	"Windows Notification Service URLs required for Live Response are reachable.`r`n")
	#}
}

# Test for existence of unsupported ProcessMitigationOptions and dump IFEO
# Reference https://docs.microsoft.com/en-us/windows/security/threat-protection/override-mitigation-options-for-app-related-security-policies
Get-childItem -Recurse "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" -ErrorAction SilentlyContinue | Out-File "$resultOutputDir\SystemInfoLogs\IFEO.txt"
Get-Item "HKLM:SYSTEM\CurrentControlSet\Control\Session Manager\kernel" | Out-File "$resultOutputDir\SystemInfoLogs\SessionManager.txt"
if ((!$OSPreviousVersion) -and ($buildNumber -le "17134") -and ((Get-Service DiagTrack).Status -eq "StartPending")) {
	If (Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Value "MitigationOptions") {
		Write-output "`r`n######################## ProcessMitigations check #########################" | Out-File $connectivityCheckFile -Append
		WriteReport 142007 @() @()
		Check-Command-verified "reg.exe"
		&Reg export "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" "$resultOutputDir\SystemInfoLogs\KernelProcessMitigation.reg" /y 2>&1 | Out-Null
		Check-Command-verified "reg.exe"
		&Reg export "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe" "$resultOutputDir\SystemInfoLogs\SvchostProcessMitigation.reg" /y 2>&1 | Out-Null
	}	
}

# Test for existence of faulty EccCurves SSL settings and gather additional useful reg keys for troubleshooting
# Refernce https://docs.microsoft.com/en-us/windows-server/security/tls/manage-tls
$SSLSettings = "$resultOutputDir\SystemInfoLogs\SSL_00010002.txt"
$SCHANNEL = "$resultOutputDir\SystemInfoLogs\SCHANNEL.txt"
Get-ChildItem "HKLM:SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL" -Recurse -ErrorAction silentlycontinue | Out-File $SSLSettings
Get-ChildItem "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" -Recurse -ErrorAction silentlycontinue | Out-File $SCHANNEL
if ((Get-Content $SSLSettings) -like "*EccCurves : {}*") {
	WriteReport 132006 @() @()
} 

# Test if running on unsupported Windows 10 or 2012 RTM OS
if ((($OSProductName -match 'Windows 10') -and ($OSBuild -lt "14393")) -or ($OSBuild -eq "9200")) {
	Write-output "`r`n######################## Unsupported Win OS check #########################" | Out-File $connectivityCheckFile -Append
	WriteReport 112002 @(, @($OSBuild)) @()
}

# Test for WSAEPROVIDERFAILEDINIT event related to LSP in netsh winsock catalog
if (!$OSPreviousVersion) {
	$EventError = Get-MatchingEvent Microsoft-Windows-UniversalTelemetryClient 29 "2147952506"
	if ($EventError) {
		Write-output "`r`n############################ Winsock error check ###############################" | Out-File $connectivityCheckFile -Append
		if ((Get-ProcessMitigation -Name MsSense.exe).ExtensionPoint.DisableExtensionPoints -eq "ON") {
			WriteReport 140005 @() @()
			"This disables various extensibility mechanisms that allow DLL injection. No further action required." | Out-File $connectivityCheckFile -Append
		}
  else {
			WriteReport 142008 @() @()
			$EventError | Format-Table -Wrap | Out-File $connectivityCheckFile -Append
			Check-Command-verified "netsh.exe"
			$Winsock = &netsh winsock show catalog
			$winsock | Out-File $resultOutputDir\SystemInfoLogs\winsock_catalog.txt
			if ($winsock -like "*FwcWsp64.dll*") {
				WriteReport 142009 @() @()
			}
		}
	}
}

# Dump FSUTIL USN queryjournal output to log
$DriveLetters = (Get-PSDrive -PSProvider FileSystem) | Where-Object { $_.Free -ne $null } | ForEach-Object { $_.Name }
Write-output "`r`n######################## FSUTIL USN journal query #########################" | Out-File $connectivityCheckFile -Append
foreach ($DriveLetter in $DriveLetters) {
	Write-output "USN query journal output for Drive: " $DriveLetter | Out-File $connectivityCheckFile -Append
	Check-Command-verified "fsutil.exe"
	&fsutil usn queryjournal ("$DriveLetter" + ":") |  Out-File $connectivityCheckFile -Append
}

# Dump AddRemovePrograms to file
$uninstallKeys = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
$dstfile = "$resultOutputDir\SystemInfoLogs\AddRemovePrograms.csv"
GetAddRemovePrograms $uninstallKeys | Export-Csv -Path $dstfile -NoTypeInformation -Encoding UTF8
$uninstallKeysWOW64 = Get-ChildItem HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall -ErrorAction SilentlyContinue
$dstfileWOW64 = "$resultOutputDir\SystemInfoLogs\AddRemoveProgramsWOW64.csv"
if ($uninstallKeysWOW64) {
	GetAddRemovePrograms $uninstallKeysWOW64 | Export-Csv -Path $dstfileWOW64 -NoTypeInformation -Encoding UTF8
}

# Check for issues with certificate store or time skew
if (($OSPreviousVersion) -and (Test-Path -Path $env:SystemRoot\System32\'Winevt\Logs\Operations Manager.evtx')) {
	$EventError = Get-MatchingEvent "Service Connector" 3009 "80090016"
	if ($EventError) {
		Write-output "`r`n###################### MMA certificate error check #########################" | Out-File $connectivityCheckFile -Append
		WriteReport 122006 @() @()
		$EventError | Format-Table -Wrap | Out-File $connectivityCheckFile -Append
	}
	$EventError = Get-MatchingEvent "Service Connector" 4002 "ClockSkew"
	if ($EventError) {
		Write-output "`r`n######################### Client TimeSkew check ############################" | Out-File $connectivityCheckFile -Append	
		WriteReport 122007 @() @()
		$EventError | Format-Table -Wrap | Out-File $connectivityCheckFile -Append
	}
}

# Check for issues with Default paths or reg keys
# Taken from amcore/wcd/Source/Setup/Manifest/Windows-SenseClient-Service.man
$DefaultPaths = 
@{
	Name = "Default MDE Policies key"
	Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection"
},
@{
	Name = "Default MDE Sensor Service key"
	Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Sense"
},
@{
	Name = "Default MDE directory path"
	Path = "$env:ProgramFiles\Windows Defender Advanced Threat Protection"
},
@{
	Name = "Default MDE ProgramData directory path"
	Path = "$env:ProgramData\Microsoft\Windows Defender Advanced Threat Protection"
},
@{
	Name = "Default MDE Cache directory path"
	Path = "$env:ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Cache"
},
@{
	Name = "Default MDE Cyber directory path"
	Path = "$env:ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Cyber"
},
@{
	Name = "Default MDE Temp directory path"
	Path = "$env:ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Temp"
},
@{
	Name = "Defalt MDE Trace directory path"
	Path = "$env:ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Trace"
}

if ((!$OSPreviousVersion) -and (!$ARM) -and ($buildNumber -ge "15063")) {
	foreach ($item in $DefaultPaths) {
		if (!(Test-Path $item.Path)) {
			$MissingDefaultPath += $("`r`n" + $item.Name)
			$MissingDefaultPath += $("`r`n" + $item.Path + "`n")
		}
	}
	if ($MissingDefaultPath) {
		Write-Host -BackgroundColor Red -ForegroundColor Yellow "Default paths are missing. Please ensure the missing path(s) exist and have not been renamed:"
		Write-Host $MissingDefaultPath
		Write-output "`r`n###################### Missing default path check #########################" | Out-File $connectivityCheckFile -Append
		WriteReport 122003 @(, @($MissingDefaultPath)) @(, @($DefaultPaths[5].Path))
	}
}

# Check if SENSE cannot be started due to crash
if ((!$OSPreviousVersion) -or ($MDfWS)) {
	$EventError = (Get-MatchingEvent "Application Error" 1000 "TelLib.dll")
	if ($EventError) {
		$EventError | Format-Table -Wrap | Out-File $connectivityCheckFile -Append
		$Exception = ($EventError.message -split '\n')[2]
		[DateTime]$Timeframe = ($EventError.TimeCreated)
        [DateTime]$DaysAgo = (Get-Date).AddDays(-2)
        if (($DaysAgo -gt $Timeframe) -and ((Get-Service SENSE).Status -eq "Running")) {
			Write-output "`r`n Crash Event was detected but it is older than 2 days while SENSE service is running as expected now" | Out-File $connectivityCheckFile -Append
        } else {
            WriteReport 122039 @(, @($Exception)) @()
        }
	}
	# Check for PPL protection 
	Check-Command-verified "sc.exe"
	#Checking only for ": WINDOWS" string as a quick fix for this test on non-English OSes
	$qprotection = (&sc.exe qprotection sense)
	if ($qprotection[1].contains(": WINDOWS")) {
		WriteReport 110005 @() @()
	} elseif (($qprotection[1].contains(": ANTIMALWARE")) -And ($buildNumber -eq "14393") -And ($OSEditionName -match "Client")) {
		WriteReport 110005 @() @()
	} else {
		WriteReport 112004 @(, @($qprotection[1])) @()
	}
}

# Check if onboarding failed with Access denied due to tampering with registry permissions
if ((Test-Path -Path "$env:ProgramFiles\Windows Defender Advanced Threat Protection\MsSense.exe") -and !(Get-Process -Name MsSense -ErrorAction silentlycontinue)) {
	$EventError = (Get-MatchingEvent Microsoft-Windows-SENSE 43 "80070005")
	if ($EventError) {
		$EventError | Format-Table -Wrap | Out-File $connectivityCheckFile -Append
		$SenseRegAclList = (Get-Acl -Path HKLM:\System\CurrentControlSet\Services\Sense | Select-Object -ExpandProperty Access) 
		$SenseRegAclSystem = $SenseRegAclList | Where-Object identityreference -eq "NT AUTHORITY\SYSTEM" 
		if (($SenseRegAclSystem.RegistryRights -ne "FullControl") -or ($SenseRegAclSystem.AccessControlType -ne "Allow")) {
			[string]$cleanAclOutput = $SenseRegAclSystem | Out-String -Width 250
			WriteReport 122015 @() @(, @($cleanAclOutput))	
		}
	}
} 

# Check if onboarding via SCCM failed due to registry issues
if (test-path -path $env:windir\ccm\logs\DcmWmiProvider.log) {
	$SCCMErr = Select-String -Path $env:windir\ccm\logs\DcmWmiProvider.log -Pattern 'Unable to update WATP onboarding' | Sort-Object CreationTime -Unique
	if ($SCCMErr) { 
		Write-output "`r`n############################ SCCM onboarding check ###############################" | Out-File $connectivityCheckFile -Append
		Copy-Item -path $env:windir\ccm\logs\DcmWmiProvider.log -Destination "$resultOutputDir\EventLogs\DcmWmiProvider.log"
		WriteReport 122004 @() @(, @($SCCMErr))
	}
}

# Check if onboarding via MMA failed due to unsupported OS env
if (Test-Path -Path $env:SystemRoot\System32\'Winevt\Logs\Operations Manager.evtx') {
	$EventError = Get-MatchingEvent "HealthService" 4509 "NotSupportedException"
	if (($EventError) -And (!$IsOnboarded)) {
		Write-output "`r`n########################## MMA unsupported OS check ##########################" | Out-File $connectivityCheckFile -Append
		WriteReport 112020 @() @()
		$EventError | Format-Table -Wrap | Out-File $connectivityCheckFile -Append
	}
}

# Check if running latest SCEP edition for downlevel OS
$SCEP = GetAddRemovePrograms $uninstallKeys | Where-Object { $_.DisplayName -like "*Endpoint Protection" }
if ($SCEP -And ("$env:ProgramFiles\Microsoft Security Client\")) {	
	if ([version](($SCEP).DisplayVersion) -lt [version]"4.10.209.0") {
		Write-output "`r`n############################ SCEP Client check ###############################" | Out-File $connectivityCheckFile -Append	
		WriteReport 122008 @(, @($SCEP)) @()
	}
}

Write-output "`r`n################## MDE CommandLine usage information ####################"  | Out-File $connectivityCheckFile -Append 
[environment]::GetCommandLineArgs() | Out-File $connectivityCheckFile -Append


Write-Host "Generating HealthCheck report..."
GenerateHealthCheckReport

# Check if MSinfo is still running and allow to run until timeout is reached
EndTimedoutProcess "msinfo32" 5

# collect Mde Configuration Manager logs reg and Events
get-MdeConfigMgrLog

[version]$PSMinVer = '2.0.1.1'
if ( $PSVersionTable.PSVersion -gt $PSMinVer) {
	Write-Host "Compressing results directory..."
	Add-Type -Assembly "System.IO.Compression.FileSystem";
	[System.IO.Compression.ZipFile]::CreateFromDirectory($resultOutputDir, $outputZipFile)
	Write-Host "Result is available at: " $outputZipFile
}
else {
	Write-Host "Result is available at: " $resultOutputDir
}

# Prompt user to open HTML result file
if (!($system -or $RemoteRun -or $AdvancedFlag) -and ($HtmOutputFile)) {
	<# 
	Write-Host -ForegroundColor Green "Enter ANY key to view a summary of the Client Analyzer results or 'N' to exit"
	$ShowResults = Read-Host
	if ($ShowResults -ne "N") {
		Start-Process -FilePath $HtmOutputFile   
    }
	#>
	Write-Host -ForegroundColor Green "Opening the client analysis results in browser"
	Start-Process -FilePath $HtmOutputFile   
}

# SIG # Begin signature block
# MIIntwYJKoZIhvcNAQcCoIInqDCCJ6QCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA5OpGYyeMO1SUm
# HeOsK8XN25D4yGCMke/5slNFE/1PNaCCDZcwggYVMIID/aADAgECAhMzAAADEBr/
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
# zTGCGXYwghlyAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEC
# EzMAAAMQGv99cNuNb0MAAAAAAxAwDQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcN
# AQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUw
# LwYJKoZIhvcNAQkEMSIEIEU6Er6PKqpjrDijkVYjly5yagp1o/9U6niQPYwVLYOh
# MEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEBBQAEggEASBkha6ODIofG
# DrohpQzOlHH/i2pkP8c/0kt4/BWD6yEOt4ufHPLDv03T4Ofk7HYcl89k6rpiRGU/
# cH6FTqqtZN0Uk7bnPCK6jl69IulwWkbA5MjAQbgk9i/rBkLvWPoVwAsLxGdtggZu
# HJqcXgXkYIDld8NLFoawjWUQBGbOXPzxj/HGPLNyJlHcHWK1H95vUpcZoEWBhtWa
# brB/H8ipUhRd/PyZ1RvhQaibagOJ5LtbePkheEwish/3acmaAW4c5yhkFdVg8V3z
# J35o+Ssie+hCTqX94KVDK+Hp1fT2MWlZTbynQz93HrBstxL3dEcSXg3RzuNSYHAv
# Wbpv81TkpKGCFwAwghb8BgorBgEEAYI3AwMBMYIW7DCCFugGCSqGSIb3DQEHAqCC
# FtkwghbVAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFRBgsqhkiG9w0BCRABBKCCAUAE
# ggE8MIIBOAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUABCAfgz5RmUTX
# 4mSTLU6HNgK4GU/3VA4x3mymta9N5h2/UgIGY0hKSKyOGBMyMDIyMTAyNjA3NTcy
# Ny42MjNaMASAAgH0oIHQpIHNMIHKMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25z
# MSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo0OUJDLUUzN0EtMjMzQzElMCMGA1UE
# AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCCEVcwggcMMIIE9KADAgEC
# AhMzAAABlwPPWZxriXg/AAEAAAGXMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIxMTIwMjE5MDUxNFoXDTIzMDIyODE5MDUx
# NFowgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNV
# BAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxl
# cyBUU1MgRVNOOjQ5QkMtRTM3QS0yMzNDMSUwIwYDVQQDExxNaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA
# 7QBK6kpBTfPwnv3LKx1VnL9YkozUwKzyhDKij1E6WCV/EwWZfPCza6cOGxKT4pjv
# hLXJYuUQaGRInqPks2FJ29PpyhFmhGILm4Kfh0xWYg/OS5Xe5pNl4PdSjAxNsjHj
# iB9gx6U7J+adC39Ag5XzxORzsKT+f77FMTXg1jFus7ErilOvWi+znMpN+lTMgiox
# zTC+u1ZmTCQTu219b2FUoTr0KmVJMQqQkd7M5sR09PbOp4cC3jQs+5zJ1OzxIjRl
# cUmLvldBE6aRaSu0x3BmADGt0mGY0MRsgznOydtJBLnerc+QK0kcxuO6rHA3z2Kr
# 9fmpHsfNcN/eRPtZHOLrpH59AnirQA7puz6ka20TA+8MhZ19hb8msrRo9LmirjFx
# SbGfsH3ZNEbLj3lh7Vc+DEQhMH2K9XPiU5Jkt5/6bx6/2/Od3aNvC6Dx3s5N3UsW
# 54kKI1twU2CS5q1Hov5+ARyuZk0/DbsRus6D97fB1ZoQlv/4trBcMVRz7MkOrHa8
# bP4WqbD0ebLYtiExvx4HuEnh+0p3veNjh3gP0+7DkiVwIYcfVclIhFFGsfnSiFex
# ruu646uUla+VTUuG3bjqS7FhI3hh6THov/98XfHcWeNhvxA5K+fi+1BcSLgQKvq/
# HYj/w/Mkf3bu73OERisNaacaaOCR/TJ2H3fs1A7lIHECAwEAAaOCATYwggEyMB0G
# A1UdDgQWBBRtzwHPKOswbpZVC9Gxvt1+vRUAYDAfBgNVHSMEGDAWgBSfpxVdAF5i
# XYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jv
# c29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENB
# JTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRp
# bWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4ICAQAESNhh0iTtMx57IXLf
# h4LuHbD1NG9MlLA1wYQHQBnR9U/rg3qt3Nx6e7+QuEKMEhKqdLf3g5RR4R/oZL5v
# EJVWUfISH/oSWdzqrShqcmT4Oxzc2CBs0UtnyopVDm4W2Cumo3quykYPpBoGdeir
# vDdd153AwsJkIMgm/8sxJKbIBeT82tnrUngNmNo8u7l1uE0hsMAq1bivQ63fQInr
# +VqYJvYT0W/0PW7pA3qh4ocNjiX6Z8d9kjx8L7uBPI/HsxifCj/8mFRvpVBYOyqP
# 7Y5di5ZAnjTDSHMZNUFPHt+nhFXUcHjXPRRHCMqqJg4D63X6b0V0R87Q93ipwGIX
# BMzOMQNItJORekHtHlLi3bg6Lnpjs0aCo5/RlHCjNkSDg+xV7qYea37L/OKTNjqm
# H3pNAa3BvP/rDQiGEYvgAbVHEIQz7WMWSYsWeUPFZI36mCjgUY6V538CkQtDwM8B
# DiAcy+quO8epykiP0H32yqwDh852BeWm1etF+Pkw/t8XO3Q+diFu7Ggiqjdemj4V
# fpRsm2tTN9HnAewrrb0XwY8QE2tp0hRdN2b0UiSxMmB4hNyKKXVaDLOFCdiLnsfp
# D0rjOH8jbECZObaWWLn9eEvDr+QNQPvS4r47L9Aa8Lr1Hr47VwJ5E2gCEnvYwIRD
# zpJhMRi0KijYN43yT6XSGR4N9jCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkA
# AAAAABUwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRl
# IEF1dGhvcml0eSAyMDEwMB4XDTIxMDkzMDE4MjIyNVoXDTMwMDkzMDE4MzIyNVow
# fDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMd
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggIiMA0GCSqGSIb3DQEBAQUA
# A4ICDwAwggIKAoICAQDk4aZM57RyIQt5osvXJHm9DtWC0/3unAcH0qlsTnXIyjVX
# 9gF/bErg4r25PhdgM/9cT8dm95VTcVrifkpa/rg2Z4VGIwy1jRPPdzLAEBjoYH1q
# UoNEt6aORmsHFPPFdvWGUNzBRMhxXFExN6AKOG6N7dcP2CZTfDlhAnrEqv1yaa8d
# q6z2Nr41JmTamDu6GnszrYBbfowQHJ1S/rboYiXcag/PXfT+jlPP1uyFVk3v3byN
# pOORj7I5LFGc6XBpDco2LXCOMcg1KL3jtIckw+DJj361VI/c+gVVmG1oO5pGve2k
# rnopN6zL64NF50ZuyjLVwIYwXE8s4mKyzbnijYjklqwBSru+cakXW2dg3viSkR4d
# Pf0gz3N9QZpGdc3EXzTdEonW/aUgfX782Z5F37ZyL9t9X4C626p+Nuw2TPYrbqgS
# Uei/BQOj0XOmTTd0lBw0gg/wEPK3Rxjtp+iZfD9M269ewvPV2HM9Q07BMzlMjgK8
# QmguEOqEUUbi0b1qGFphAXPKZ6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJNmSLW6Cm
# gyFdXzB0kZSU2LlQ+QuJYfM2BjUYhEfb3BvR/bLUHMVr9lxSUV0S2yW6r1AFemzF
# ER1y7435UsSFF5PAPBXbGjfHCBUYP3irRbb1Hode2o+eFnJpxq57t7c+auIurQID
# AQABo4IB3TCCAdkwEgYJKwYBBAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3FQIEFgQU
# KqdS/mTEmr6CkTxGNSnPEP8vBO4wHQYDVR0OBBYEFJ+nFV0AXmJdg/Tl0mWnG1M1
# GelyMFwGA1UdIARVMFMwUQYMKwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0
# dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0
# bTATBgNVHSUEDDAKBggrBgEFBQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMA
# QTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbL
# j+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1p
# Y3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0w
# Ni0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIz
# LmNydDANBgkqhkiG9w0BAQsFAAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL/Klv6lwU
# tj5OR2R4sQaTlz0xM7U518JxNj/aZGx80HU5bbsPMeTCj/ts0aGUGCLu6WZnOlNN
# 3Zi6th542DYunKmCVgADsAW+iehp4LoJ7nvfam++Kctu2D9IdQHZGN5tggz1bSNU
# 5HhTdSRXud2f8449xvNo32X2pFaq95W2KFUn0CS9QKC/GbYSEhFdPSfgQJY4rPf5
# KYnDvBewVIVCs/wMnosZiefwC2qBwoEZQhlSdYo2wh3DYXMuLGt7bj8sCXgU6ZGy
# qVvfSaN0DLzskYDSPeZKPmY7T7uG+jIa2Zb0j/aRAfbOxnT99kxybxCrdTDFNLB6
# 2FD+CljdQDzHVG2dY3RILLFORy3BFARxv2T5JL5zbcqOCb2zAVdJVGTZc9d/HltE
# AY5aGZFrDZ+kKNxnGSgkujhLmm77IVRrakURR6nxt67I6IleT53S0Ex2tVdUCbFp
# AUR+fKFhbHP+CrvsQWY9af3LwUFJfn6Tvsv4O+S3Fb+0zj6lMVGEvL8CwYKiexcd
# FYmNcP7ntdAoGokLjzbaukz5m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9JZTmdHRb
# atGePu1+oDEzfbzL6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQd
# VTNYs6FwZvKhggLOMIICNwIBATCB+KGB0KSBzTCByjELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2Eg
# T3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046NDlCQy1FMzdBLTIz
# M0MxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAH
# BgUrDgMCGgMVAGFA0rCNmEk0zU12DYNGMU3B1mPRoIGDMIGApH4wfDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDnA0LjMCIYDzIw
# MjIxMDI2MTMyMzQ3WhgPMjAyMjEwMjcxMzIzNDdaMHcwPQYKKwYBBAGEWQoEATEv
# MC0wCgIFAOcDQuMCAQAwCgIBAAICDGECAf8wBwIBAAICE2owCgIFAOcElGMCAQAw
# NgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgC
# AQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQAXaJ98RBAOzuH38WIbUlterzwukP4E
# ezXL7NEbEsGpFBdIIIIQzCzbwPcmutEM6Eo19cBvIS0sxGaa6iputTtKhKwu3Ynk
# CWt6Xm7wrUShbr7c7lfl8e6LUcLlo//FW0IPmXi/ac5FGzB62JIgSCUZ9Ggc2dSe
# 56qU/yaDt0v8PzGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
# QSAyMDEwAhMzAAABlwPPWZxriXg/AAEAAAGXMA0GCWCGSAFlAwQCAQUAoIIBSjAa
# BgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIL1hexhE
# pg8zQ42ZTatE0uytjBgMxtDwu3Mv4sBJZCXPMIH6BgsqhkiG9w0BCRACLzGB6jCB
# 5zCB5DCBvQQgW3vaGxCVejj+BAzFSfMxfHQ+bxxkqCw8LkMY/QZ4pr8wgZgwgYCk
# fjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQD
# Ex1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAZcDz1mca4l4PwAB
# AAABlzAiBCAn03LRx18kUdWvY6ewrn8JURenkDZi3lYKQJljL7qyJTANBgkqhkiG
# 9w0BAQsFAASCAgCkaChY5VMrqwzG93+2e1BCkZRQL45Cln5KVnJ3wXTMAy8OrsWD
# osIinkDl7XxgGhDHflFPiPyCtNHNGGwn72EAqzIA6iudMYW/YumxGo4qsOZkEhLn
# 4ihc+7DJwUGYI0V4l4cvF2qBKdl77gKWL9eCVEyHm2+Vp/ib8Zk1NTk5y9yucfe0
# nmCzU0KLWMIzDcBUj1i6DFfR9NY0pqXfwC3cdcUjqPKbBibjECr3qTiDZSsa7TJ/
# 0r+KaLOpmGGiIOBiwcqFoyx6zRTHpxTZMoqeHuTLunsoUUnbhS0Rb776EkayU+9C
# WMypytTKIambDqh5qWPLNVo6PT1rtxjdqRUPh8t0QmEtq1wB408A+UTNhsbgD50R
# uEvvaUM2v3wwcDt2oUVT4qskyLW1er075BJs57XN31apcYvtQ+PWpJwyiqvO4Xor
# KSpX38833VfMNGw1DJnkxzSziEZjfFtDPNS51aI/wJS1IuwTJMXFrsOIGKzsc+Vx
# MYeiZRA0GzNSu+wqHy3reWl0qZrmuc4zRLiwAhgt0STA3z9VJpiV1xLcZ35Y3o9l
# aEkzjbm3jQ5FhSBONpiHRiCKM0rjHwIxBezS7gQZvwmZLyQQQdkfUqi3WEHEdnEj
# 9ERK8EOwkXpflyCdw4m72Q9GMM916ZKd4cD6jlJbbNvD5PAk9oMcqDuN2w==
# SIG # End signature block
