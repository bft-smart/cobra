set TEMP_DIR=C:\Users\robin\Desktop
set SRC=C:\Users\robin\\Documents\IntelliJ\COBRA
set FOLDER_NAME=cobraQ
set QUINTA_USER=rvassantlal

set DST=%TEMP_DIR%\%FOLDER_NAME%

rmdir /s /q %DST%
rem mkdir %DST%

rem del %TEMP_DIR%\%FOLDER_NAME%.zip

xcopy %SRC%\bin\*.jar %DST%\bin\
rem xcopy %SRC%\pairing\headers\* %DST%\pairing\headers\
rem xcopy %SRC%\pairing\relic\*.zip %DST%\pairing\relic\
rem xcopy %SRC%\pairing\src\* %DST%\pairing\src\
rem xcopy %SRC%\pairing\*.sh %DST%\pairing\
rem xcopy %SRC%\lib\Ver*.jar %DST%\lib\
rem xcopy %SRC%\*.sh %DST%\
xcopy /e /q %SRC%\config\*.config %DST%\config\
rem xcopy %SRC%\scripts\*.sh %DST%\

rem del %DST%\config\currentView
del %DST%\config\hosts.config
rmdir /s /q %DST%\config\keysECDSA
rmdir /s /q %DST%\config\keysRSA
rmdir /s /q %DST%\config\keysSSL_TLS
rmdir /s /q %DST%\config\keysSunEC
rmdir /s /q %DST%\config\workloads

scp -r %DST% %QUINTA_USER%@quinta.navigators.di.fc.ul.pt:/home/users/%QUINTA_USER%