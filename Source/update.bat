@echo off

set update_url=%1

IF "%1"=="" (
    set update_url="https://github.com/OpenRMM/Agent.git"
)
CD C:\OpenRMM\
"C:\Program Files\Git\bin\git" clone %update_url% temp
robocopy /IS /E /MOVE /IM "temp\source\" "Agent\"

CD C:\OpenRMM\Agent\Py
py OpenRMM.py update
py OpenRMM.py restart
::start py OpenRMM.py debug
pause
