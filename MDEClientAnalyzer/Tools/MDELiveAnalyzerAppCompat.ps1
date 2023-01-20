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
    &powershell -ExecutionPolicy Bypass "& 'C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Downloads\MDEClientAnalyzer.ps1' -outputDir 'C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Downloads' -r -c"
}
# SIG # Begin signature block
# MIIntwYJKoZIhvcNAQcCoIInqDCCJ6QCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBjeLvlZEeKzf5i
# dWUflcUoP3Zq+gamfKpabU8x/KRq+qCCDZcwggYVMIID/aADAgECAhMzAAADEBr/
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
# LwYJKoZIhvcNAQkEMSIEIMRKZGv03kZ58GZ5wxyQ1jSHEEsUOIRL60I49RkDxjTr
# MEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEBBQAEggEARXcBIeGuzlk/
# oWcqOc9I8ltQJiLFvCnsiD25bl4CPsi93hm26zpDYxdZW92u35+quTNZDj0WJ75Z
# JJhBoC94fUjZMEcRtuh88Tspoz5mQbf7ge8b4j4TWBJdIksb3XiQtYNxBGVEozE3
# R206GwGQcxr+NMPf6Vf/N7BL21IVqmRVWJq7rNet9qDXMQbscDRNuLYsCPG7r+YH
# hGztgTPdvcd2K8OfEjsV7ibbyn/wnhZOCENEh7mh+0pZjNyLC5J2nlSzs3c46aXo
# kbfugRic2pmakdIzBIFopW90fkaRZ6FzUvlJMDkPV1qKMWfXzkwK2A/RlnwF5ixm
# nb0sMQrYk6GCFwAwghb8BgorBgEEAYI3AwMBMYIW7DCCFugGCSqGSIb3DQEHAqCC
# FtkwghbVAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFRBgsqhkiG9w0BCRABBKCCAUAE
# ggE8MIIBOAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUABCA24+811R0C
# N+UeSk9TH6FlvkV075441KuMSA548ij6YQIGY0g2g4fvGBMyMDIyMTAyNjA3NTcy
# Ny40NTRaMASAAgH0oIHQpIHNMIHKMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25z
# MSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpFNUE2LUUyN0MtNTkyRTElMCMGA1UE
# AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCCEVcwggcMMIIE9KADAgEC
# AhMzAAABlbf8DdbjNzElAAEAAAGVMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIxMTIwMjE5MDUxMloXDTIzMDIyODE5MDUx
# MlowgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNV
# BAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxl
# cyBUU1MgRVNOOkU1QTYtRTI3Qy01OTJFMSUwIwYDVQQDExxNaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA
# n21BDGe2Szs/WqEQniS+IYU/UPCWQdsWlZTDQrd28IXEyORiz67dnvdwwLJpajs8
# NXBYjz4OkubCwl8+y221EKS4WvEuL9qnHDLU6JBGg0EvkCRK5wLJelUpkbwMtJ5Y
# /gvz2mbi29zs2NAEcO1HgmS6cljzx/pOTHWI+jVA0zaF6m80Bwrj7Pn4CKK6Octw
# x6DtO+4OiK9kxyMdcn1RRLecw3BTzmDIOMgYuAOl3N4ZvbWesPOPZwb1SsJuWAC3
# x98v395+C5zetW9cMwMd2QmY39d1Cm6RO6eg2Cax0Qf/qcBYxvfU8Bx+rl8w3mU+
# v6+qh+wAAcJ/H6WHNU5pXhWPGEblc846fVZDx1fFc78yy+0CtpLXnlyy/2OJb4y+
# oc8jphPtS1Q95RG2IaNcwrfhe21PhaY8gX0wuIv8B7KbW9tfGJW5ELdYtQepZZic
# FRcAi1+4MUOPECBlGnDMvJKdfs3M2PksZaWhIDZkJH3Na2j4fcubDGul+PPsdCuw
# fDqg6F3E4hAiIyXrccLbgZULHidOR0X4rH4BZtPZBu73RxKNzW1LjDARYpHOG6Df
# VH5tIlIavybaldCsK7/Qr92sg4HTcBFoi9muuSJxFkqUU2H7AkNN3qhIeQN68Ffy
# n1BXIrfg6z/vVXA6Y1kbAqJGb+LYJ+agFzTLR2vDYqkCAwEAAaOCATYwggEyMB0G
# A1UdDgQWBBSrl9NiAhRXV4K3AgZgyXx+b/ypFzAfBgNVHSMEGDAWgBSfpxVdAF5i
# XYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jv
# c29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENB
# JTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRp
# bWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4ICAQDgszbeHyfozr0LqtCL
# Z9+yGa2DQRrMAIviABTN2Biv8BkJRJ3II5jQbmnPeVtnwC+sbRVXzH5HqkizC6qI
# nVbFPQZuAxAY2ljTk/bl/7XGIiUnxUDNKw265fFeJzPPEWReehv6iVvYOXSKjkqI
# psylLf0O1h+lQcltLGq+cBr4KLyt6hWncCkoc0WHBKk5Bx9s4qeXu943szx8dvrW
# mKiRucSc3QxK2dZzIsUY2h7NyqXLJmWLsbCEXwWDibwBRspkxkb+T7sLDabPRHId
# QGrKvOB/2P/MTdxkI+D9zIg5/Is1AQwrlyHx2JN/W6p2gJhW1Igm8vllqbs3ZOKA
# ys/7FsK57KEO9rhBlRDe/pMsPfh0qOYvJfGYNWJo/bVIA6VVBowHbqC8h0O16pJy
# pkvZCUgSpOKJBA4NCHei3ii0MB9XuGlXk8lGMHAV98IO6SyUFr0e52tkhq7Zf9t2
# BkE7nZljq8ocfZZ1OygRlf2jb89LU6XLLnLCvnGRSgxJFgf6FBVa7crp+jQ+aWGT
# Y9AoEbqeYK1QAqvwIG/hDhiwg/sxLRjaKeLXyr7GG+uNuezSfV6zB4KQom++lk9+
# ET5ggQcsS1JB8R6ucwsmDbtCBVwLdQFYnMNeDPnMy2CFTOzTslaRXXAdQfTIiYpO
# 6XkootF00XZef1fyrHE2ggRc9zCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkA
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
# T3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RTVBNi1FMjdDLTU5
# MkUxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAH
# BgUrDgMCGgMVANGPgsi3sxoFR1hTZiiNS7hP4WOroIGDMIGApH4wfDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDnAy85MCIYDzIw
# MjIxMDI2MTE1OTUzWhgPMjAyMjEwMjcxMTU5NTNaMHcwPQYKKwYBBAGEWQoEATEv
# MC0wCgIFAOcDLzkCAQAwCgIBAAICFPkCAf8wBwIBAAICEaQwCgIFAOcEgLkCAQAw
# NgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgC
# AQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQAeozYXD6jmFZs7VgUB9OHeFPs+Y6KO
# 58DVi3JhZskIF1xnGWxmTAhno0ZoXM1fAmopRIs8wVGKGNkbUvVPljdGV5sqO0GZ
# VoCAHhKJ2q5QQ4oIYTKl08fj/5GzV+HH0Qo8wuxVbC6eCaob7tnE6H7rkveXjCQG
# LAl2Z1RO+QfwZTGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
# QSAyMDEwAhMzAAABlbf8DdbjNzElAAEAAAGVMA0GCWCGSAFlAwQCAQUAoIIBSjAa
# BgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIP1wAM91
# LkvECzhSz636I3ECm7zUgTyEkev7WW9zlwAlMIH6BgsqhkiG9w0BCRACLzGB6jCB
# 5zCB5DCBvQQgXOZL4Y2QC3tpoSM/0He5HlTpgP3AtXcymU+MmyxJAscwgZgwgYCk
# fjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQD
# Ex1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAZW3/A3W4zcxJQAB
# AAABlTAiBCDRbg+3z40igGuznQhgxmYlqM6FIQFSJl83VrdOYOj5oDANBgkqhkiG
# 9w0BAQsFAASCAgBSIt/Jc2EPX0FJp0nPPjK21/Mh4YW6C9VeXnBQ+TtvyrOuF2oE
# U6YLYog0LHWfdTmrBk5b/t2m428BUWQGQkkGA1YubmQvSUBN+1bel3egWNpuWepM
# LB/A/siQAxv/ioApYIwlWRNlOP3SaF+Ve1JYYbD4DIA7Sv/2A32M5WUGwBDnBXNN
# EDg2c7DHsnC8WbDNgG4T1dKhZZ9GMCVQ8T2wSs8emB/i0d3HeTZoVkdC6xZMT9X6
# agqziBV6iv1FpHSVUIfwETH1hTOMVGn9JNS47YbjZYw3X09R8xwWJ7cYa2GM471D
# 2WN/JvQIwSF23AbM7ekqfcmGGyGz18o9PN1AnDa3lNC76H31poOuaIVCEcTLlwDG
# UHPQiUbYjQ99zyhKcanZfdUq+C3U80EbVcvTpLtZihEk6JPtVEQL3R4qwH0c8MuM
# xKNFzXy+l2BLKxFpaUHW9E1JT0PUr90JVcIrUq7ynihsZzkcqcRUPDdN2m6OQliw
# Xps7gIvREmGIdmlQ2i7uvIfbTebGWD78o/KicWjFqhRPmf24gfpaGzI7dtOj5RBG
# WwqY69zEKHMKD8zxgFcDVZeW8ESo39YopZvxN/wV6UA/mkI7Kk9y8hAECIOUkg2h
# ruE1tmv9peRS5ruzb27zcLMVK6i/xNmfs1xTm2IrUmjHSVkZrj6VM1k5tQ==
# SIG # End signature block
