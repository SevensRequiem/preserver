@echo off
setlocal enableextensions
rem Installs preserver, preserver-gui and the Task Scheduler tasks. See CLAUDE.md, "Install and release".
rem   install.bat [RELEASE_DIR]   preserver-TARGET.exe (and preserver-gui-TARGET.exe) and SHA256SUMS from a release, or build this checkout
rem   install.bat /rollback       swap back to the previous binaries
rem   install.bat /uninstall      remove the binaries, the Start Menu shortcut and the tasks (data and keys stay)
rem The binary's own "install" subcommand is not implemented yet (phase 5), so the tasks are made here.

set "BIN=%LOCALAPPDATA%\preserver\bin"
set "EXE=%BIN%\preserver.exe"
set "PREV=%BIN%\preserver.prev.exe"
set "GUI=%BIN%\preserver-gui.exe"
set "GPREV=%BIN%\preserver-gui.prev.exe"
set "LNK=%APPDATA%\Microsoft\Windows\Start Menu\Programs\preserver.lnk"
set "WORK=%BIN%\.install"
set "SELF=%~dp0"

if /i "%~1"=="/rollback" goto rollback
if /i "%~1"=="/uninstall" goto uninstall
if /i "%~1"=="/?" goto usage
if /i "%~1"=="-h" goto usage
if not "%~2"=="" goto usage
if "%LOCALAPPDATA%"=="" (echo install.bat: LOCALAPPDATA is not set 1>&2 & exit /b 1)
echo "%BIN%" | findstr /r /c:"[&<>%%^]" >nul && (echo install.bat: unsupported character in "%BIN%" 1>&2 & exit /b 1)

set "ARCH=%PROCESSOR_ARCHITECTURE%"
if defined PROCESSOR_ARCHITEW6432 set "ARCH=%PROCESSOR_ARCHITEW6432%"
if /i "%ARCH%"=="AMD64" (set "TARGET=x86_64-pc-windows-msvc") else if /i "%ARCH%"=="ARM64" (set "TARGET=aarch64-pc-windows-msvc") else (echo install.bat: no release binary for %ARCH% 1>&2 & exit /b 1)

if not exist "%BIN%" mkdir "%BIN%"
if exist "%WORK%" rmdir /s /q "%WORK%"
mkdir "%WORK%" || exit /b 1

if "%~1"=="" goto fromsource

set "REL=%~1"
set "NAME=preserver-%TARGET%.exe"
set "GNAME=preserver-gui-%TARGET%.exe"
if not exist "%REL%\%NAME%" (echo install.bat: "%REL%\%NAME%" not found 1>&2 & goto fail)
if not exist "%REL%\SHA256SUMS" (echo install.bat: "%REL%\SHA256SUMS" not found 1>&2 & goto fail)
call :verify "%NAME%" preserver.exe || goto fail
if exist "%REL%\%GNAME%" (call :verify "%GNAME%" preserver-gui.exe || goto fail) else if exist "%GUI%" echo install.bat: this release has no %GNAME%: left "%GUI%" as it is
goto install

:fromsource
if not exist "%SELF%Cargo.toml" (echo install.bat: no Cargo.toml next to this script: pass a release directory 1>&2 & goto fail)
pushd "%SELF%" || goto fail
cargo build --release --locked --features gui || (popd & goto fail)
popd
if defined CARGO_TARGET_DIR (set "BUILT=%CARGO_TARGET_DIR%\release") else (set "BUILT=%SELF%target\release")
for %%b in (preserver.exe preserver-gui.exe) do (
  if not exist "%BUILT%\%%b" (echo install.bat: build did not produce "%BUILT%\%%b" 1>&2 & goto fail)
  copy /y "%BUILT%\%%b" "%WORK%\%%b" >nul || goto fail
)

:install
schtasks /End /TN "\preserver\tray" >nul 2>&1
schtasks /End /TN "\preserver\daemon" >nul 2>&1
set "PLACED_EXE="
set "PLACED_GUI="
call :place preserver.exe "%EXE%" "%PREV%" PLACED_EXE || goto fail
if exist "%WORK%\preserver-gui.exe" (
  call :place preserver-gui.exe "%GUI%" "%GPREV%" PLACED_GUI || goto fail
  call :shortcut
)
rem /rollback undoes the last install, so a .prev it did not write (an older install's) goes.
if defined PLACED_EXE if not defined PLACED_GUI del /f /q "%GPREV%" 2>nul
if defined PLACED_GUI if not defined PLACED_EXE del /f /q "%PREV%" 2>nul

chcp 65001 >nul
call :tasklogon "%WORK%\tray.xml" tray
call :tasklogon "%WORK%\daemon.xml" daemon
schtasks /Create /TN "\preserver\tray" /XML "%WORK%\tray.xml" /F >nul || goto fail
schtasks /Create /TN "\preserver\daemon" /XML "%WORK%\daemon.xml" /F >nul || goto fail
rem The daemon runs these jobs now, on the times under [schedule] in config.toml.
for %%t in (local public) do (
  schtasks /End /TN "\preserver\%%t" >nul 2>&1
  schtasks /Delete /TN "\preserver\%%t" /F >nul 2>&1
)
schtasks /Run /TN "\preserver\tray" >nul 2>&1
schtasks /Run /TN "\preserver\daemon" >nul 2>&1
rmdir /s /q "%WORK%"
echo install.bat: tasks \preserver\tray and \preserver\daemon (at logon) are registered; backups run on the times under [schedule] in config.toml
exit /b 0

:rollback
if not exist "%PREV%" if not exist "%GPREV%" (echo install.bat: no previous binary at %PREV% or %GPREV% 1>&2 & exit /b 1)
schtasks /End /TN "\preserver\tray" >nul 2>&1
schtasks /End /TN "\preserver\daemon" >nul 2>&1
if exist "%PREV%" (
  if exist "%EXE%" (move /y "%EXE%" "%BIN%\preserver.swap.exe" >nul || exit /b 1)
  move /y "%PREV%" "%EXE%" >nul || exit /b 1
  if exist "%BIN%\preserver.swap.exe" move /y "%BIN%\preserver.swap.exe" "%PREV%" >nul
)
if exist "%GPREV%" (
  if exist "%GUI%" (move /y "%GUI%" "%BIN%\preserver-gui.swap.exe" >nul || exit /b 1)
  move /y "%GPREV%" "%GUI%" >nul || exit /b 1
  if exist "%BIN%\preserver-gui.swap.exe" move /y "%BIN%\preserver-gui.swap.exe" "%GPREV%" >nul
)
schtasks /Run /TN "\preserver\tray" >nul 2>&1
schtasks /Run /TN "\preserver\daemon" >nul 2>&1
echo install.bat: rolled back what the last install replaced: preserver and/or preserver-gui; run /rollback again to swap forward
exit /b 0

:uninstall
for %%t in (tray daemon local public) do (
  schtasks /End /TN "\preserver\%%t" >nul 2>&1
  schtasks /Delete /TN "\preserver\%%t" /F >nul 2>&1
)
del /f /q "%EXE%" "%PREV%" "%GUI%" "%GPREV%" "%LNK%" 2>nul
echo install.bat: removed the binaries, their previous versions, the Start Menu shortcut and the tasks; config, keys, state and backups are untouched
exit /b 0

:usage
echo usage: install.bat [RELEASE_DIR] ^| /rollback ^| /uninstall 1>&2
exit /b 2

:fail
if exist "%WORK%" rmdir /s /q "%WORK%"
exit /b 1

:verify
rem %1 is the file in REL, %2 the name it is staged as. Hash the staged copy, not the download,
rem so what is checked is what gets installed.
set "WANT="
set "COUNT=0"
for /f "usebackq tokens=1,2" %%a in ("%REL%\SHA256SUMS") do (
  if /i "%%b"=="%~1" (set "WANT=%%a" & set /a COUNT+=1)
  if /i "%%b"=="*%~1" (set "WANT=%%a" & set /a COUNT+=1)
)
if not "%COUNT%"=="1" (echo install.bat: SHA256SUMS needs exactly one entry for %~1, nothing installed 1>&2 & exit /b 1)
copy /y "%REL%\%~1" "%WORK%\%~2" >nul || exit /b 1
call :hash "%WORK%\%~2" GOT || exit /b 1
if /i not "%GOT%"=="%WANT%" (echo install.bat: checksum mismatch for %~1, nothing installed 1>&2 & exit /b 1)
echo install.bat: checksum ok for %~1
exit /b 0

:place
rem %1 is the staged name, %2 the installed path, %3 its .prev, %4 a variable set when it replaced anything.
if exist %2 fc /b %2 "%WORK%\%~1" >nul 2>&1 && (echo install.bat: %2 is already this binary & exit /b 0)
if not exist %2 del /f /q %3 2>nul
set "%~4=1"
rem A running exe can be renamed but not overwritten, so the old one moves to .prev first.
if exist %2 (move /y %2 %3 >nul || exit /b 1 & echo install.bat: kept the previous binary as %3)
move /y "%WORK%\%~1" %2 >nul || exit /b 1
echo install.bat: installed %~2
exit /b 0

:shortcut
rem The paths reach PowerShell through the environment, never through the command text.
set "PRESERVER_GUI=%GUI%"
set "PRESERVER_LNK=%LNK%"
powershell -NoProfile -NonInteractive -Command "$s = (New-Object -ComObject WScript.Shell).CreateShortcut($env:PRESERVER_LNK); $s.TargetPath = $env:PRESERVER_GUI; $s.WorkingDirectory = Split-Path -Parent $env:PRESERVER_GUI; $s.Save()" >nul 2>&1 && (echo install.bat: Start Menu shortcut "%LNK%") || echo install.bat: warning: could not create the Start Menu shortcut 1>&2
exit /b 0

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

:tasklogon
call :xmlhead %1
>>%1 echo     ^<LogonTrigger^>^<Enabled^>true^</Enabled^>^<UserId^>%USERDOMAIN%\%USERNAME%^</UserId^>^</LogonTrigger^>
call :xmltail %1 true 7 %2
exit /b 0

