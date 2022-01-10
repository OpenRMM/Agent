@echo off

set update_url=%1

IF "%1"=="" (
    set update_url="https://github.com/OpenRMM/Agent.git"
)

CD C:\OpenRMM\
git clone %update_url% temp
xcopy /e /v /XN temp\source\ Agent\

CD C:\OpenRMM\Agent\Py
py OpenRMM.py update
py OpenRMM.py start
::start py OpenRMM.py debug
EXIT