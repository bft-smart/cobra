set SRC=D:\IntelliJ\Confidential-BFT-SMaRt
set DST=C:\Users\robin\Desktop\bft-smart
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
	for /d %%i in (%DST%\rep*) do rmdir /s /q %%i
	for %%a in (%REP%) do (
		mkdir %DST%\rep%%a
		xcopy %SRC%\bin\* %DST%\rep%%a\bin\
		xcopy %SRC%\lib\* %DST%\rep%%a\lib\
		xcopy /e /q %SRC%\config\* %DST%\rep%%a\config\
		xcopy %SRC%\scripts\*.cmd %DST%\rep%%a\
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
	for /d %%i in (%DST%\cli*) do rmdir /s /q %%i
	for %%a in (%CLI%) do (
		mkdir %DST%\cli%%a
		xcopy %SRC%\bin\* %DST%\cli%%a\bin\
		xcopy %SRC%\lib\* %DST%\cli%%a\lib\
		xcopy /e /q %SRC%\config\* %DST%\cli%%a\config\
		xcopy %SRC%\scripts\*.cmd %DST%\cli%%a\
		del %DST%\cli%%a\config\currentView
		IF %cmd%==y (
			start "cli%%a" /d %DST%\cli%%a
		)
	)
)