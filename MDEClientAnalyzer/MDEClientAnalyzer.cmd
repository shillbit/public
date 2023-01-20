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
echo MDEClientAnalyzer.cmd ^<-h ^| -l ^| -c ^|-i ^|-b ^|-a ^| -v^| -t^> [-d] [-z] [-k]
echo.
echo -h	Collect extensive Windows performance tracing for analysis of a performance scenario that can be reproduced on demand.
echo:
echo -l	Collect perfmon counters and sensor tracing for analysis of a long-running or gradual performance degradation scenario.
echo:
echo -c	Collect screenshots, procmon and sensor tracing for analysis of an application compatiblity sceanrio which can be reproduced on demand.
echo:
echo -i	Collect network, firewall and sensor tracing for analysis of isolation/Unisolation issues which can be reproduced on demand.
echo:
echo -b	Collect ProcMon logs during startup (will restart the machine for data collection).
echo:
echo -a	Collect extensive Windows performance tracing for analysis of Windows Defender (MsMpEng.exe) high CPU scenarios.
echo:
echo -v	Collect verbose Windows Defender (MsMpEng.exe) tracing for analysis of various antimalware scenarios.
echo:
echo -t	Collect tracing for analysis of various DLP related scenarios.
echo:
echo -q	Collect quick DLPDiagnose output for validation of DLP client health.
echo:
echo -d	Collect a memory dump of the sensor process. Note: '-d' can be used in combination with any of the above parameters.
echo:
echo -z	Prepare the machine for full memory dump collection (requires reboot).
echo:
echo -k	Send a command to the machine to crash immediately and generate a memory dump for advanced debugging purposes.
echo.

GOTO :END

:MAIN
rem The below is used to avoid calling 32bit powershell in case 32bit CMD is used on 64bit OS:
if "%PROCESSOR_ARCHITEW6432%" == "" (set precommand=) else (set precommand=%systemroot%\sysnative\cmd.exe /c)
%precommand% powershell.exe  -ExecutionPolicy Bypass "& '%~dpn0.ps1' -outputDir '%~dp0' %*"

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