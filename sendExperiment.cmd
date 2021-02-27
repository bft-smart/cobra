set TEMP_DIR=C:\Users\robin\Desktop
set SRC=F:\IntelliJ\COBRA
set FOLDER_NAME=cobraQ
set QUINTA_USER=rvassantlal

set DST=%TEMP_DIR%\%FOLDER_NAME%

rmdir /s /q %DST%
rem mkdir %DST%

rem del %TEMP_DIR%\%FOLDER_NAME%.zip

xcopy %SRC%\bin\*.jar %DST%\bin\
rem xcopy /e /q %SRC%\pairing\* %DST%\pairing\
rem xcopy %SRC%\lib\BFT*.jar %DST%\lib\
rem xcopy %SRC%\*.sh %DST%\
rem xcopy /e /q %SRC%\config\* %DST%\config\
rem xcopy %SRC%\scripts\*.sh %DST%\

del %DST%\config\currentView
del %DST%\config\hosts.config
rmdir /s /q %DST%\config\keysECDSA
rmdir /s /q %DST%\config\keysRSA
rmdir /s /q %DST%\config\keysSSL_TLS
rmdir /s /q %DST%\config\keysSunEC
rmdir /s /q %DST%\config\workloads

scp -r %DST% %QUINTA_USER%@quinta.navigators.di.fc.ul.pt:/home/users/%QUINTA_USER%