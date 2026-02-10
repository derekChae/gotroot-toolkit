@echo off
setlocal

if /i "%~1"=="start" goto start
if /i "%~1"=="install" goto install
if /i "%~1"=="init" goto init
if /i "%~1"=="save" goto save
if /i "%~1"=="push" goto push
if /i "%~1"=="pull" goto pull
if /i "%~1"=="status" goto status
if /i "%~1"=="log" goto log
goto help

:install
echo [*] Installing dependencies...
pip install -r requirements.txt
goto end

:start
echo.
echo   GOTROOT Recon Agent
echo   ====================
echo   Starting server...
echo   Open: http://localhost:8000
echo.
python server.py
goto end

:init
echo [*] Initializing git repository...
git init
git remote add origin %~2
git add -A
git commit -m "init: GOTROOT Recon Agent"
echo [OK] Repository initialized. Run: gr push
goto end

:save
if "%~2"=="" (
    git add -A
    git commit -m "update: %date% %time%"
) else (
    git add -A
    git commit -m "%~2"
)
echo [OK] Changes saved.
goto end

:push
git push -u origin main
echo [OK] Pushed to remote.
goto end

:pull
git pull origin main
echo [OK] Pulled latest.
goto end

:status
git status
goto end

:log
git log --oneline -10
goto end

:help
echo.
echo   GOTROOT Recon Agent - Commands
echo   ================================
echo.
echo   gr install     Install Python dependencies
echo   gr start       Start the web server
echo   gr init [url]  Initialize git + add remote
echo   gr save [msg]  Git add + commit
echo   gr push        Push to GitHub
echo   gr pull        Pull from GitHub
echo   gr status      Git status
echo   gr log         Show recent commits
echo.
goto end

:end
endlocal
