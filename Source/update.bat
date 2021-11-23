@echo off

set update_url=%1

IF "%1"=="" (
    set update_url="https://raw.githubusercontent.com/OpenRMM/Agent/main/Source"
)

:PowerShell
SET PSScript=%temp%\~tmpDlFile.ps1
IF EXIST "%PSScript%" DEL /Q /F "%PSScript%"
ECHO [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls">>"%PSScript%"
ECHO Invoke-WebRequest "%update_url%/Py/OpenRMM.py" -OutFile "C:\OpenRMM\Agent\Py\OpenRMM.py">>"%PSScript%"
ECHO Invoke-WebRequest "%update_url%/Py/UI.py" -OutFile "C:\OpenRMM\Agent\Py\UI.py">>"%PSScript%"
ECHO Invoke-WebRequest "%update_url%/EXE/speedtest.exe" -OutFile "C:\OpenRMM\Agent\EXE\speedtest.exe">>"%PSScript%"
ECHO Invoke-WebRequest "%update_url%/update.bat" -OutFile "C:\OpenRMM\Agent\update.bat">>"%PSScript%"
ECHO Invoke-WebRequest "%update_url%/icon.ico" -OutFile "C:\OpenRMM\Agent\icon.ico">>"%PSScript%"

SET PowerShellDir=C:\Windows\System32\WindowsPowerShell\v1.0
CD /D "%PowerShellDir%"
Powershell -ExecutionPolicy Bypass -Command "& '%PSScript%'"
CD C:\OpenRMM\Agent\Py
py OpenRMM.py update
py OpenRMM.py start
::start py OpenRMM.py debug
EXIT