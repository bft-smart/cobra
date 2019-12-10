set SRC=D:\IntelliJ\COBRA
set DST=C:\Users\robin\Desktop\cobra
set REP=0 1 2 3
set CLI=0

IF "%1"=="open" (
    set cmd=y
) ELSE (
    set cmd=n
)

rem :PROMP
rem set /p replica=Copy Server code?[y/n]

set replica=y

IF %replica%==y (
	rem for /d %%i in (%DST%\rep*) do rmdir /s /q %%i
	for %%a in (%REP%) do (
		mkdir /p %DST%\rep%%a
		xcopy /d /y %SRC%\bin\* %DST%\rep%%a\bin\
		xcopy /d /y %SRC%\lib\* %DST%\rep%%a\lib\
		xcopy /s /y /D %SRC%\pairing\* %DST%\rep%%a\pairing\
		xcopy /d /y %SRC%\pairing_based_execution* %DST%\rep%%a
		xcopy /e /y /q /d %SRC%\config\* %DST%\rep%%a\config\
		xcopy /d /y %SRC%\scripts\* %DST%\rep%%a\
		del %DST%\rep%%a\config\currentView
		IF %cmd%==y (
			start "rep%%a" /d %DST%\rep%%a
		)
	)
)

rem :PROMP
rem set /p client=Copy Client code?[y/n]
set client=y

IF %client%==y (
	rem for /d %%i in (%DST%\cli*) do rmdir /s /q %%i
	for %%a in (%CLI%) do (
		mkdir %DST%\cli%%a
		xcopy /D /Y %SRC%\bin\* %DST%\cli%%a\bin\
		xcopy /D /Y %SRC%\lib\* %DST%\cli%%a\lib\
		xcopy /S /Y /D %SRC%\pairing\* %DST%\cli%%a\pairing\
        xcopy /D /Y %SRC%\pairing_based_execution* %DST%\rep%%a
		xcopy /E /Y /Q /D %SRC%\config\* %DST%\cli%%a\config\
		xcopy /D /Y %SRC%\scripts\* %DST%\cli%%a\
		del %DST%\cli%%a\config\currentView
		IF %cmd%==y (
			start "cli%%a" /d %DST%\cli%%a
		)
	)
)