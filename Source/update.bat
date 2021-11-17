@echo off

set update_url=%1

IF "%1"=="" (
    set update_url="https://raw.githubusercontent.com/OpenRMM/Agent/main/Source/OpenRMM.py"
)

:PowerShell
SET PSScript=%temp%\~tmpDlFile.ps1
IF EXIST "%PSScript%" DEL /Q /F "%PSScript%"
ECHO [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls">>"%PSScript%"
ECHO Invoke-WebRequest %update_url% -OutFile "C:\OpenRMM\Agent\OpenRMM.py">>"%PSScript%"

SET PowerShellDir=C:\Windows\System32\WindowsPowerShell\v1.0
CD /D "%PowerShellDir%"
Powershell -ExecutionPolicy Bypass -Command "& '%PSScript%'"
CD C:\OpenRMM\Agent
py OpenRMM.py update
::start py OpenRMM.py start
start py OpenRMM.py debug
EXIT