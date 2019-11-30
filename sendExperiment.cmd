set TEMP_DIR=C:\Users\robin\Desktop
set SRC=D:\IntelliJ\COBRA
set FOLDER_NAME=cobraQ
set QUINTA_USER=rvassantlal

set DST=%TEMP_DIR%\%FOLDER_NAME%

rmdir /s /q %DST%
rem mkdir %DST%

rem del %TEMP_DIR%\%FOLDER_NAME%.zip

xcopy %SRC%\bin\*.jar %DST%\bin\
xcopy %SRC%\pairing\headers\* %DST%\pairing\headers\
xcopy %SRC%\pairing\relic\*.zip %DST%\pairing\relic\
xcopy %SRC%\pairing\src\* %DST%\pairing\src\
xcopy %SRC%\pairing\*.sh %DST%\pairing\
rem xcopy %SRC%\lib\*.jar %DST%\lib\
rem xcopy /e /q %SRC%\config\* %DST%\config\
rem xcopy %SRC%\scripts\*.sh %DST%\

rem del %DST%\config\currentView
rem del %DST%\config\hosts.config
rem rmdir /s /q %DST%\config\keysECDSA
rem rmdir /s /q %DST%\config\keysRSA
rem rmdir /s /q %DST%\config\keysSSL_TLS
rem rmdir /s /q %DST%\config\keysSunEC
rem rmdir /s /q %DST%\config\workloads

scp -r %DST% %QUINTA_USER%@quinta.navigators.di.fc.ul.pt:/home/users/%QUINTA_USER%