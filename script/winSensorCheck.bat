@echo off&color 0f

echo ******查找敏感目录********************************************
echo *查看%AppData%..\..\Local\Temp\
dir /s /o:-d %AppData%..\..\Local\Temp\"*.exe"
dir /s /o:-d %AppData%..\..\Local\Temp\"*.zip"
dir /s /o:-d %AppData%..\..\Local\Temp\"*.rar"
dir /s /o:-d %AppData%..\..\Local\Temp\"*.7z"
dir /s /o:-d %AppData%..\..\Local\Temp\"*.log"
dir /s /o:-d %AppData%..\..\Local\Temp\"*.ini"
echo=

echo *查看%WINDIR%\temp\
dir /s /o:-d %WINDIR%\temp\"*.exe*"
dir /s /o:-d %WINDIR%\temp\"*.zip*"
dir /s /o:-d %WINDIR%\temp\"*.rar*"
dir /s /o:-d %WINDIR%\temp\"*.7z*"
dir /s /o:-d %WINDIR%\temp\"*.log*"
dir /s /o:-d %WINDIR%\temp\"*.ini*"

echo *查看C:\Perflogs\
dir /s /o:-d C:\Perflogs\"*exe*"
dir /s /o:-d C:\Perflogs\"*.zip*"
dir /s /o:-d C:\Perflogs\"*.rar*"
dir /s /o:-d C:\Perflogs\"*.7z*"
dir /s /o:-d C:\Perflogs\"*.log*"
dir /s /o:-d C:\Perflogs\"*.ini*"

echo *查看C:\ProgramData\
dir /s /o:-d C:\ProgramData\"*exe*"
dir /s /o:-d C:\ProgramData\"*.zip*"
dir /s /o:-d C:\ProgramData\"*.rar*"
dir /s /o:-d C:\ProgramData\"*.7z*"
dir /s /o:-d C:\ProgramData\"*.log*"
dir /s /o:-d C:\ProgramData\"*.ini*"

echo *查看%public%\
dir /s /o:-d %public%\"*exe*"
dir /s /o:-d %public%\"*.zip*"
dir /s /o:-d %public%\"*.rar*"
dir /s /o:-d %public%\"*.7z*"
dir /s /o:-d %public%\"*.log*"
dir /s /o:-d %public%\"*.ini*"

echo *查看%startup%\
dir "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup"

::echo *查看%UserProfile%\Recent
::dir /s /o:-d %UserProfile%\Recent\"*.exe*"
::dir /s /o:-d %UserProfile%\Recent\"*.zip*"
::dir /s /o:-d %UserProfile%\Recent\"*.rar*"
::dir /s /o:-d %UserProfile%\Recent\"*.7z*"
::dir /s /o:-d %UserProfile%\Recent\"*.log*"
::dir /s /o:-d %UserProfile%\Recent\"*.ini*"
::同样的结果 %UserProfile%\Recent & %APPDATA%\Microsoft\Windows\Recent
echo *查看最近打开文件%APPDATA%\Microsoft\Windows\Recent
dir /o:-d %APPDATA%\Microsoft\Windows\Recent

echo *查看%UserProfile%\downloads
dir /s /o:-d %UserProfile%\downloads\"*.exe*"
dir /s /o:-d %UserProfile%\downloads\"*.zip*"
dir /s /o:-d %UserProfile%\downloads\"*.rar*"
dir /s /o:-d %UserProfile%\downloads\"*.7z*"
dir /s /o:-d %UserProfile%\downloads\"*.log*"
dir /s /o:-d %UserProfile%\downloads\"*.ini*"
echo=

echo *查看最近打开程序
dir /o:-d %WINDIR%\Prefetch
echo=

echo ******检查anydesk*********************************************
dir *%appdata%\anydesk\
echo ==============================================================
echo=
echo=

echo ******检查向日葵**********************************************
type *%programdata%\oray\sunloginclient\log\*
