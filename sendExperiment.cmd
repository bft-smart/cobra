set TEMP_DIR=C:\Users\robin\Desktop
set SRC=D:\IntelliJ\Confidential-BFT-SMaRt
set FOLDER_NAME=confidential
set QUINTA_USER=rvassantlal

set DST=%TEMP_DIR%\%FOLDER_NAME%

rmdir /s /q %DST%
rem mkdir %DST%

rem del %TEMP_DIR%\%FOLDER_NAME%.zip

xcopy %SRC%\bin\*.jar %DST%\bin\
xcopy %SRC%\lib\BFT* %DST%\lib\
rem xcopy /e /q %SRC%\config\* %DST%\config\
rem xcopy %SRC%\scripts\*.sh %DST%\

del %DST%\config\currentView
rmdir /s /q %DST%\config\keysECDSA
rmdir /s /q %DST%\config\keysRSA
rmdir /s /q %DST%\config\keysSSL_TLS
rmdir /s /q %DST%\config\keysSunEC
rmdir /s /q %DST%\config\workloads

scp -r %DST% %QUINTA_USER%@quinta.navigators.di.fc.ul.pt:/home/users/%QUINTA_USER%