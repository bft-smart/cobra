set TEMP_DIR=C:\Users\robin\Desktop
set SRC=F:\IntelliJ\COBRA
set FOLDER_NAME=cobraQ
set QUINTA_USER=testbed

set DST=%TEMP_DIR%\%FOLDER_NAME%

rmdir /s /q %DST%
rem mkdir %DST%

rem del %TEMP_DIR%\%FOLDER_NAME%.zip

xcopy %SRC%\bin\*.jar %DST%\bin\
xcopy /e /q %SRC%\pairing\* %DST%\pairing\
xcopy %SRC%\lib\*.jar %DST%\lib\
xcopy %SRC%\*.sh %DST%\
xcopy /e /q %SRC%\config\* %DST%\config\
xcopy %SRC%\scripts\*.sh %DST%\

del %DST%\config\currentView
rem del %DST%\config\hosts.config
rem rmdir /s /q %DST%\config\keysECDSA
rem rmdir /s /q %DST%\config\keysRSA
rem rmdir /s /q %DST%\config\keysSSL_TLS
rem rmdir /s /q %DST%\config\keysSunEC
rem rmdir /s /q %DST%\config\workloads

scp -r %DST% %QUINTA_USER%@192.168.10.100:~/