@ECHO OFF
:: BatchGotAdmin
::-------------------------------------
REM  --> Check for permissions
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

REM --> If error flag set, we do not have admin.
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params = %*:"="
    echo UAC.ShellExecute "cmd.exe", "/c %~s0 %params%", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    pushd "%CD%"
    CD /D "%~dp0"
::--------------------------------------


CD Source
echo "Installing Python 3.9.7"
python-3.9.7.exe /quiet InstallAllUsers=1 PrependPath=1
echo "Installing Required Modules"
py -m pip install paho-mqtt
py -m pip install pyautogui
py -m pip install pywin32
py -m pip install wmi
py -m pip install pillow
py -m pip install scandir
py -m pip install speedtest-cli
echo "Moving DLLs"
echo moving %USERPROFILE%\AppData\Roaming\Python\Python39\site-packages\pywin32_system32
Xcopy /E /I %USERPROFILE%\AppData\Roaming\Python\Python39\site-packages\pywin32_system32 %USERPROFILE%\AppData\Roaming\Python\Python39\site-packages\win32\lib\pywin32_system32

echo "Installing OpenRMM Agent"
py OpenRMM.py install
echo "Running OpenRMM Agent"
py OpenRMM.py debug
pause