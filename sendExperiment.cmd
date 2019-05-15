set TEMP_DIR=C:\Users\robin\Desktop
set SRC=D:\IntelliJ\Confidential-BFT-SMaRt
set FOLDER_NAME=confidential
set QUINTA_USER=rvassantlal

set DST=%TEMP_DIR%\%FOLDER_NAME%

rem rmdir /s /q %DST%
rem mkdir %DST%

rem del %TEMP_DIR%\%FOLDER_NAME%.zip

xcopy %SRC%\bin\*.jar %DST%\bin\
xcopy %SRC%\lib\*.jar %DST%\lib\
xcopy /e /q %SRC%\config\* %DST%\config\
xcopy %SRC%\scripts\*.sh %DST%\


scp -r %DST% %QUINTA_USER%@quinta.navigators.di.fc.ul.pt:/home/users/%QUINTA_USER%

rem jar cMfv %TEMP_DIR%\%ZIP_NAME%.zip -C %DST%\ .

rem scp %TEMP_DIR%\%ZIP_NAME%.zip %QUINTA_USER%@quinta.navigators.di.fc.ul.pt:/home/users/%QUINTA_USER%