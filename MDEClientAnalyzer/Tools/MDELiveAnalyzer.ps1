#Enforcing default PSModulePath to avoid getting unexpected modules to run instead of built-in modules
$env:PSModulePath = "C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules"
$resultOutputDir = "C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Downloads\MDEClientAnalyzerResult"

function CheckAuthenticodeSignature($pathToCheck) {
	If (Test-Path -path $pathToCheck -ErrorAction SilentlyContinue) {
		$AuthenticodeSig = (Get-AuthenticodeSignature -FilePath $pathToCheck)
		$cert = $AuthenticodeSig.SignerCertificate
		$FileInfo = (get-command $pathToCheck).FileVersionInfo
		if (test-path $resultOutputDir -ErrorAction SilentlyContinue) {
		    $issuerInfo = "$resultOutputDir\issuerInfo.txt"
        } else {
            $issuerInfo = "$PSScriptRoot\issuerInfo.txt"
        }
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

function Download-WebFile($ClientAnalyzer) {    
    Write-host -ForegroundColor Green "Downloading MDEClientAnalyzer from: " $ClientAnalyzer
       Import-Module BitsTransfer
       $BitsJob = Start-BitsTransfer -source $ClientAnalyzer -Destination "$DlZipFile" -Description "Downloading additional files" -RetryTimeout 60 -RetryInterval 60 -ErrorAction SilentlyContinue
}
$DownloadDir = "C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Downloads"
$DlZipFile = Join-Path $DownloadDir "MDEClientAnalyzerPreview.zip"
$ToolsDir = Join-Path $DownloadDir "Tools"
CheckAuthenticodeSignature $MyInvocation.MyCommand.Path

if (!(test-path –path "$DlZipFile")) {
    Download-WebFile "https://aka.ms/Betamdeanalyzer"    
}
if  (test-path –path "$DlZipFile") {
    Remove-item '$DownloadDir\MDEClientAnalyzer.ps1' -Force -ErrorAction SilentlyContinue
    Remove-Item '$ToolsDir\*.*' -Force -ErrorAction SilentlyContinue
    Expand-Archive -Path $DlZipFile -DestinationPath $DownloadDir -Force -ErrorAction SilentlyContinue
	CheckAuthenticodeSignature "C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Downloads\MDEClientAnalyzer.ps1"
    &powershell -ExecutionPolicy Bypass "& 'C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Downloads\MDEClientAnalyzer.ps1' -outputDir 'C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Downloads'"
}








# SIG # Begin signature block
# MIIn4wYJKoZIhvcNAQcCoIIn1DCCJ9ACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD+lLkiiy3IQ3J6
# glhCvzr8tB1E0Djt4Sf2PhkY933Hy6CCDZcwggYVMIID/aADAgECAhMzAAADEBr/
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
# LwYJKoZIhvcNAQkEMSIEIAKBk8oUbSbrb2S5vauvgyydaaxr1OqmkD29wkqXQvY8
# MEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEBBQAEggEAIcnG4Zs6Ffy2
# bgJ8WtZeZzgC0nOCqo9lQi7LDPlfoIN2h69+hm5lTjiGKjrzcTT5Z9lrwkJ3nHCg
# 45umb1sZoEfIYJNG/bzUW9Ymm1yG13iKXB0XeWQPDFd5AqifyAIhBeDJ8GtJRbye
# UisLBv+OtqidKulSp3oyMibsAauZ7RPmb00g+RHzMZGiI5NZQVUPZgLvoUz7bLRX
# /yndiaI7lwPIhrnZ8w8oW03KPujsXnJqArhosms5Z4vPNK6AU++qEDBSDA3u8Cb5
# IuE15/Sz0/0e+TzbugO452ap3ygSelWXAhFh/x/tPds7psUE9BFeKJlLOMebExgq
# TluhxFuAWaGCFywwghcoBgorBgEEAYI3AwMBMYIXGDCCFxQGCSqGSIb3DQEHAqCC
# FwUwghcBAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFZBgsqhkiG9w0BCRABBKCCAUgE
# ggFEMIIBQAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUABCBxapG2NpjE
# tYRwjA1Eb5kH7rQYIDM4cVXgxAZEN3C7pQIGY0/rO3m7GBMyMDIyMTAyNjA3NTcy
# NC42NThaMASAAgH0oIHYpIHVMIHSMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25z
# IExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjhENDEtNEJGNy1CM0I3
# MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloIIRezCCBycw
# ggUPoAMCAQICEzMAAAGz/iXOKRsbihwAAQAAAbMwDQYJKoZIhvcNAQELBQAwfDEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWlj
# cm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjIwOTIwMjAyMjAzWhcNMjMx
# MjE0MjAyMjAzWjCB0jELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVk
# MSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo4RDQxLTRCRjctQjNCNzElMCMGA1UE
# AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBALR8D7rmGICuLLBggrK9je3hJSpc9CTwbra/4Kb2eu5D
# ZR6oCgFtCbigMuMcY31QlHr/3kuWhHJ05n4+t377PHondDDbz/dU+q/NfXSKr1pw
# U2OLylY0sw531VZ1sWAdyD2EQCEzTdLD4KJbC6wmAConiJBAqvhDyXxJ0Nuvlk74
# rdVEvribsDZxzClWEa4v62ENj/HyiCUX3MZGnY/AhDyazfpchDWoP6cJgNCSXmHV
# 9XsJgXJ4l+AYAgaqAvN8N+EpN+0TErCgFOfwZV21cg7vgenOV48gmG/EMf0LvRAe
# irxPUu+jNB3JSFbW1WU8Z5xsLEoNle35icdET+G3wDNmcSXlQYs4t94IWR541+Ps
# UTkq0kmdP4/1O4GD54ZsJ5eUnLaawXOxxT1fgbWb9VRg1Z4aspWpuL5gFwHa8UNM
# RxsKffor6qrXVVQ1OdJOS1JlevhpZlssSCVDodMc30I3fWezny6tNOofpfaPrtwJ
# 0ukXcLD1yT+89u4uQB/rqUK6J7HpkNu0fR5M5xGtOch9nyncO9alorxDfiEdb6ze
# qtCfcbo46u+/rfsslcGSuJFzlwENnU+vQ+JJ6jJRUrB+mr51zWUMiWTLDVmhLd66
# //Da/YBjA0Bi0hcYuO/WctfWk/3x87ALbtqHAbk6i1cJ8a2coieuj+9BASSjuXkB
# AgMBAAGjggFJMIIBRTAdBgNVHQ4EFgQU0BpdwlFnUgwYizhIIf9eBdyfw40wHwYD
# VR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZO
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIw
# VGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBc
# BggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0
# cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQwDAYD
# VR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAOBgNVHQ8BAf8EBAMC
# B4AwDQYJKoZIhvcNAQELBQADggIBAFqGuzfOsAm4wAJfERmJgWW0tNLLPk6VYj53
# +hBmUICsqGgj9oXNNatgCq+jHt03EiTzVhxteKWOLoTMx39cCcUJgDOQIH+Gjuyj
# YVVdOCa9Fx6lI690/OBZFlz2DDuLpUBuo//v3e4Kns412mO3A6mDQkndxeJSsdBS
# bkKqccB7TC/muFOhzg39mfijGICc1kZziJE/6HdKCF8p9+vs1yGUR5uzkIo+68q/
# n5kNt33hdaQ234VEh0wPSE+dCgpKRqfxgYsBT/5tXa3e8TXyJlVoG9jwXBrKnSQb
# 4+k19jHVB3wVUflnuANJRI9azWwqYFKDbZWkfQ8tpNoFfKKFRHbWomcodP1bVn7k
# KWUCTA8YG2RlTBtvrs3CqY3mADTJUig4ckN/MG6AIr8Q+ACmKBEm4OFpOcZMX0cx
# asopdgxM9aSdBusaJfZ3Itl3vC5C3RE97uURsVB2pvC+CnjFtt/PkY71l9UTHzUC
# O++M4hSGSzkfu+yBhXMGeBZqLXl9cffgYPcnRFjQT97Gb/bg4ssLIFuNJNNAJub+
# IvxhomRrtWuB4SN935oMfvG5cEeZ7eyYpBZ4DbkvN44ZvER0EHRakL2xb1rrsj7c
# 8I+auEqYztUpDnuq6BxpBIUAlF3UDJ0SMG5xqW/9hLMWnaJCvIerEWTFm64jthAi
# 0BDMwnCwMIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG
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
# aW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo4RDQxLTRCRjctQjNCNzEl
# MCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsO
# AwIaAxUAcYtE6JbdHhKlwkJeKoCV1JIkDmGggYMwgYCkfjB8MQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOcCUj4wIhgPMjAyMjEw
# MjUyMDE3MDJaGA8yMDIyMTAyNjIwMTcwMlowdzA9BgorBgEEAYRZCgQBMS8wLTAK
# AgUA5wJSPgIBADAKAgEAAgIKhAIB/zAHAgEAAgIRQTAKAgUA5wOjvgIBADA2Bgor
# BgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAID
# AYagMA0GCSqGSIb3DQEBBQUAA4GBAE6UyxTC6zL54bbfOoRPPSHeL9v0kApk2mnj
# eUgTFIWKdlUVb/MJt96xgTEk4RCJAEjOxGgv+aws4tnxTzIb19adVaHNiqWw1VbR
# A6FOOm9SfyRQMYqOjCX/0+cqUaX2HRvo4lpTluFvm8q1H/9bRPx88xKFz4A2k5GO
# A7yLj2bmMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIw
# MTACEzMAAAGz/iXOKRsbihwAAQAAAbMwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqG
# SIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgx1pAkDEWLY+s
# omzNF9ZMVcC/wr79nceq0sotk+q/M5cwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHk
# MIG9BCCGoTPVKhDSB7ZG0zJQZUM2jk/ll1zJGh6KOhn76k+/QjCBmDCBgKR+MHwx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1p
# Y3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABs/4lzikbG4ocAAEAAAGz
# MCIEIBs9VNL0Xp6s0RdfNX0iIu5ZaKTIfmZE9nAWAtAhTQRHMA0GCSqGSIb3DQEB
# CwUABIICADjClYkgt591jnMSd5cLRjYezlOk+cARy8L+mG1k88E57a4z2tLlW8NA
# eQqDVcVl4canV/mNt2dz8CIpB9PZYoXr/jU3DmstbRWC/LnpscRwRAc4+50jZG6N
# 2y4YgFP3CDyez1y77lsgkvk3ixv+zn0wkXP493Mo7VonZTMtEPi2O+D+b+C6uTT7
# kUd/RNtQWbw9CLc3Hl+6iLqHPNRC8me3KVAeaWhO3NHxbUa6yZscuIoTTiBSIpz2
# qUsz+hxKPSjnIjQRM92gjF9dJsrF2uitkTCkXtGB+Tp2QPTQg9fkOjS329FGjN40
# id/W8CdRyPyBEgAnWwmVt5Vs5nc68rja0PxBaM71pRAhfcF8zqGLb7ani+Ktw3NI
# vPpmhV8W8nmLhZq9Ki526zcIqo7WiSExzw3u4YBkSwQq6rRRxO8FYIs/5zGAjftJ
# ReP+RYblRJ398VxEHCiCj60g4sJ3E3KybQvc3NxZElyJaT/y3YKjiQ9UtxmspJ4L
# feK4xwHAtINVWXavdG3x0mUO0glYojH+Fm+WKG5WdDM5BJJtaw+jZUexd/oHP6KE
# 0r0QnuV32PRplAEI1K5K7NqmYs6srEL8ns1MRJ7Flt6PLRZ1AEG40TE/Yh1SJ8rH
# yNck+exWTbjaGJtJbziQ6QOY66HfBUo5lgq0ZhaVJy4t4nT8D9o/
# SIG # End signature block
