@echo off
chcp 65001 > nul
echo Đang mở dự án SecureChatApp trong Visual Studio...
start "" "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\devenv.exe" "%~dp0SecureChatApp.sln"
