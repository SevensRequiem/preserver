@echo off
setlocal enableextensions
rem Installs preserver and its Task Scheduler tasks. See CLAUDE.md, "Install and release".
rem   install.bat [RELEASE_DIR]   preserver-TARGET.exe and SHA256SUMS from a release, or build this checkout
rem   install.bat /rollback       swap back to the previous binary
rem   install.bat /uninstall      remove the binary and the tasks (data and keys stay)
rem The binary's own "install" subcommand is not implemented yet (phase 5), so the tasks are made here.

set "BIN=%LOCALAPPDATA%\preserver\bin"
set "EXE=%BIN%\preserver.exe"
set "PREV=%BIN%\preserver.prev.exe"
set "WORK=%BIN%\.install"
set "SELF=%~dp0"

if /i "%~1"=="/rollback" goto rollback
if /i "%~1"=="/uninstall" goto uninstall
if /i "%~1"=="/?" goto usage
if /i "%~1"=="-h" goto usage
if not "%~2"=="" goto usage
if "%LOCALAPPDATA%"=="" (echo install.bat: LOCALAPPDATA is not set 1>&2 & exit /b 1)
echo "%BIN%" | findstr /r /c:"[&<>%%^]" >nul && (echo install.bat: unsupported character in %BIN% 1>&2 & exit /b 1)

set "ARCH=%PROCESSOR_ARCHITECTURE%"
if defined PROCESSOR_ARCHITEW6432 set "ARCH=%PROCESSOR_ARCHITEW6432%"
if /i "%ARCH%"=="AMD64" (set "TARGET=x86_64-pc-windows-msvc") else if /i "%ARCH%"=="ARM64" (set "TARGET=aarch64-pc-windows-msvc") else (echo install.bat: no release binary for %ARCH% 1>&2 & exit /b 1)

if not exist "%BIN%" mkdir "%BIN%"
if exist "%WORK%" rmdir /s /q "%WORK%"
mkdir "%WORK%" || exit /b 1

if "%~1"=="" goto fromsource

set "REL=%~1"
set "NAME=preserver-%TARGET%.exe"
if not exist "%REL%\%NAME%" (echo install.bat: %REL%\%NAME% not found 1>&2 & goto fail)
if not exist "%REL%\SHA256SUMS" (echo install.bat: %REL%\SHA256SUMS not found 1>&2 & goto fail)
set "WANT="
set "COUNT=0"
for /f "usebackq tokens=1,2" %%a in ("%REL%\SHA256SUMS") do (
  if /i "%%b"=="%NAME%" (set "WANT=%%a" & set /a COUNT+=1)
  if /i "%%b"=="*%NAME%" (set "WANT=%%a" & set /a COUNT+=1)
)
if not "%COUNT%"=="1" (echo install.bat: SHA256SUMS needs exactly one entry for %NAME% 1>&2 & goto fail)
rem Hash the staged copy, not the download, so what is checked is what gets installed.
copy /y "%REL%\%NAME%" "%WORK%\preserver.exe" >nul || goto fail
call :hash "%WORK%\preserver.exe" GOT || goto fail
if /i not "%GOT%"=="%WANT%" (echo install.bat: checksum mismatch for %NAME%, nothing installed 1>&2 & goto fail)
echo install.bat: checksum ok for %NAME%
goto install

:fromsource
if not exist "%SELF%Cargo.toml" (echo install.bat: no Cargo.toml next to this script: pass a release directory 1>&2 & goto fail)
pushd "%SELF%" || goto fail
cargo build --release --locked || (popd & goto fail)
popd
if defined CARGO_TARGET_DIR (set "BUILT=%CARGO_TARGET_DIR%\release\preserver.exe") else (set "BUILT=%SELF%target\release\preserver.exe")
if not exist "%BUILT%" (echo install.bat: build did not produce %BUILT% 1>&2 & goto fail)
copy /y "%BUILT%" "%WORK%\preserver.exe" >nul || goto fail

:install
schtasks /End /TN "\preserver\tray" >nul 2>&1
if exist "%EXE%" fc /b "%EXE%" "%WORK%\preserver.exe" >nul 2>&1 && (echo install.bat: %EXE% is already this binary & goto tasks)
rem A running exe can be renamed but not overwritten, so the old one moves to .prev first.
if exist "%EXE%" (move /y "%EXE%" "%PREV%" >nul || goto fail & echo install.bat: kept the previous binary as %PREV%)
move /y "%WORK%\preserver.exe" "%EXE%" >nul || goto fail
echo install.bat: installed %EXE%

:tasks
chcp 65001 >nul
call :tasktray "%WORK%\tray.xml"
call :tasklocal "%WORK%\local.xml" "personal --local-only" 01:30 true
call :tasklocal "%WORK%\public.xml" "public" 03:00 false
schtasks /Create /TN "\preserver\tray" /XML "%WORK%\tray.xml" /F >nul || goto fail
schtasks /Create /TN "\preserver\local" /XML "%WORK%\local.xml" /F >nul || goto fail
schtasks /Create /TN "\preserver\public" /XML "%WORK%\public.xml" /F >nul || goto fail
schtasks /Run /TN "\preserver\tray" >nul 2>&1
rmdir /s /q "%WORK%"
echo install.bat: tasks \preserver\tray (at logon) and \preserver\local (nightly 01:30) are registered
echo install.bat: \preserver\public (03:00) is registered but disabled: schtasks /Change /TN "\preserver\public" /ENABLE
exit /b 0

:rollback
if not exist "%PREV%" (echo install.bat: no previous binary at %PREV% 1>&2 & exit /b 1)
schtasks /End /TN "\preserver\tray" >nul 2>&1
if exist "%EXE%" (
  move /y "%EXE%" "%BIN%\preserver.swap.exe" >nul || exit /b 1
)
move /y "%PREV%" "%EXE%" >nul || exit /b 1
if exist "%BIN%\preserver.swap.exe" move /y "%BIN%\preserver.swap.exe" "%PREV%" >nul
schtasks /Run /TN "\preserver\tray" >nul 2>&1
echo install.bat: rolled back: %EXE% is the previous binary, %PREV% is the one replaced
exit /b 0

:uninstall
for %%t in (tray local public) do (
  schtasks /End /TN "\preserver\%%t" >nul 2>&1
  schtasks /Delete /TN "\preserver\%%t" /F >nul 2>&1
)
del /f /q "%EXE%" "%PREV%" 2>nul
echo install.bat: removed binary, previous binary and tasks; config, keys, state and backups are untouched
exit /b 0

:usage
echo usage: install.bat [RELEASE_DIR] ^| /rollback ^| /uninstall 1>&2
exit /b 2

:fail
if exist "%WORK%" rmdir /s /q "%WORK%"
exit /b 1

:hash
set "%~2="
for /f "skip=1 tokens=* delims=" %%h in ('certutil -hashfile %1 SHA256') do if not defined %~2 set "%~2=%%h"
call set "%~2=%%%~2: =%%"
exit /b 0

:xmlhead
>%1 echo ^<?xml version="1.0" encoding="UTF-8"?^>
>>%1 echo ^<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"^>
>>%1 echo   ^<Triggers^>
exit /b 0

:xmltail
>>%1 echo   ^</Triggers^>
>>%1 echo   ^<Principals^>^<Principal id="Author"^>^<UserId^>%USERDOMAIN%\%USERNAME%^</UserId^>^<LogonType^>InteractiveToken^</LogonType^>^<RunLevel^>LeastPrivilege^</RunLevel^>^</Principal^>^</Principals^>
>>%1 echo   ^<Settings^>
>>%1 echo     ^<MultipleInstancesPolicy^>IgnoreNew^</MultipleInstancesPolicy^>
>>%1 echo     ^<DisallowStartIfOnBatteries^>false^</DisallowStartIfOnBatteries^>
>>%1 echo     ^<StopIfGoingOnBatteries^>false^</StopIfGoingOnBatteries^>
>>%1 echo     ^<StartWhenAvailable^>true^</StartWhenAvailable^>
>>%1 echo     ^<Enabled^>%~2^</Enabled^>
>>%1 echo     ^<ExecutionTimeLimit^>PT0S^</ExecutionTimeLimit^>
>>%1 echo     ^<Priority^>%~3^</Priority^>
>>%1 echo   ^</Settings^>
>>%1 echo   ^<Actions Context="Author"^>
>>%1 echo     ^<Exec^>^<Command^>%EXE%^</Command^>^<Arguments^>%~4^</Arguments^>^</Exec^>
>>%1 echo   ^</Actions^>
>>%1 echo ^</Task^>
exit /b 0

:tasktray
call :xmlhead %1
>>%1 echo     ^<LogonTrigger^>^<Enabled^>true^</Enabled^>^<UserId^>%USERDOMAIN%\%USERNAME%^</UserId^>^</LogonTrigger^>
call :xmltail %1 true 7 tray
exit /b 0

:tasklocal
call :xmlhead %1
>>%1 echo     ^<CalendarTrigger^>^<StartBoundary^>2026-01-01T%~3:00^</StartBoundary^>^<Enabled^>true^</Enabled^>^<ScheduleByDay^>^<DaysInterval^>1^</DaysInterval^>^</ScheduleByDay^>^</CalendarTrigger^>
call :xmltail %1 %4 7 %2
exit /b 0
