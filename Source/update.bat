@echo off
echo starting to update the OpenRMM Agent
set update_url=%1

IF "%1"=="" (
    set update_url="https://github.com/OpenRMM/Agent.git"
)
CD C:\OpenRMM\
echo starting git clone from update source: %update_url% 
"C:\Program Files\Git\bin\git" clone %update_url% temp
echo starting copy from temp
robocopy temp\source\ Agent\ /IS /E /MOVE /IM
echo waiting 5 seconds
timeout 5
echo restarting service
CD C:\OpenRMM\Agent\Py
py OpenRMM.py update
py OpenRMM.py restart
::start py OpenRMM.py debug
echo waiting 2 seconds
timeout 2
echo deleting temp dir C:\OpenRMM\temp
CD C:\OpenRMM\
rmdir /S /Q temp
echo Update Complete
timeout 2
EXIT
