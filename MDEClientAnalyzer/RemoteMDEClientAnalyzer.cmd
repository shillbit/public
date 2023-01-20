@echo off
echo.
echo Starting Microsoft Defender for Endpoint analyzer process...
echo.
IF [%1]==[/?] GOTO :help
echo Testing for administrative privileges

net session >NUL 2>&1
if %ERRORLEVEL% NEQ 0 (
	@echo Script is running with insufficient privileges. Please run with administrator privileges> %TMP%\senseTmp.txt
	set errorCode=65
    set lastError=%ERRORLEVEL%
	GOTO ERROR
)

echo Script is running with sufficient privileges
echo.

echo %* |find "/?" > nul
IF errorlevel 1 GOTO :MAIN

:help
echo RemoteMDEClientAnalyzer.cmd [RemoteMachineNameOrIp] [FileShareWithMDEClientAnalyzer] [-ScenarioParameter] [-m #MinutesToRun]
echo.
echo Note that the result file will be placed into the file share you specify in the command.
echo.
echo Requirements: 
echo 1. File share must be accessible from the remote machine for both read and write.
echo 2. DNS resolution must be functional if using names instead of IPs.
echo 3. MDEClientAnalyzer tool must be extracted and available in the specified file share.
echo 4. The user running the script must be an administrator on the remote machine.
echo.
echo example 1:
echo RemoteMDEClientAnalyzer.cmd 192.168.101.99 \\192.168.101.1\MDE
echo.
echo example 2:
echo RemoteMDEClientAnalyzer.cmd PC1.contoso.com \\FileServer\MDE
echo.
echo example 3:
echo RemoteMDEClientAnalyzer.cmd PC1.contoso.com \\FileServer\MDE -c -m 1
echo Note: The above runs '-c' ScenarioParameter and limits the data collection to 1 minute (default is 5 minutes if '-m' is not used)
echo.
echo example 4:
echo RemoteMDEClientAnalyzer.cmd PC1.contoso.com \\FileServer\MDE -k
echo Note: The above sends a command to the remote machine to crash immediately and generate a memory dump for advanced debugging purposes 
echo.

GOTO :END

:MAIN
set host=%1
ping -n 1 "%host%" | findstr /r /c:"[0-9] *ms"
if errorlevel 1 (
	echo Failed to reach remote machine...
	GOTO :CLEANUP
) else (
	echo Ping to remote machines was successful
)

%~dp0\Tools\PsExec.exe -s \\%1 fsutil file createnew %2\test.txt 1
IF EXIST %2\test.txt (
	del %2\test.txt
	echo File share is accessible and writable 
) ELSE (
	echo File share provided is not allowing write or not reachable
	GOTO :CLEANUP
)

IF EXIST %2\MDEClientAnalyzer.cmd (
	echo File share contains MDEClientAnalyzer tool
) ELSE (
	echo File share provided does not contain MDEClientAnalyzer
	GOTO :CLEANUP
)

%~dp0\Tools\PsExec.exe -s \\%1 robocopy %2 C:\Work\tools\MDEClientAnalyzer /ZB /XO /R:1 /W:1
%~dp0\Tools\PsExec.exe -s \\%1 robocopy %2\Tools C:\Work\tools\MDEClientAnalyzer\Tools /ZB /XO /R:1 /W:1
%~dp0\Tools\PsExec.exe -s \\%1 C:\Work\tools\MDEClientAnalyzer\MDEClientAnalyzer.cmd -r %3 %4 %5 %6
%~dp0\Tools\PsExec.exe -s \\%1 robocopy C:\Work\tools\MDEClientAnalyzer %2\%1 MDEClientAnalyzerResult.zip /ZB /R:1 /W:1

GOTO CLEANUP

:ERROR
Set /P errorMsg=<%TMP%\senseTmp.txt
set "errorOutput=[Error Id: %errorCode%, Error Level: %lastError%] %errorDescription% Error message: %errorMsg%"
echo %errorOutput%
echo %troubleshootInfo%
echo.

:CLEANUP
if exist %TMP%\senseTmp.txt del %TMP%\senseTmp.txt
EXIT /B %errorCode%

:END