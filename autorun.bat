@echo off
REM AD Account Custodian - Simple Auto Runner

echo Pulling latest prod branch...
git fetch origin
git checkout prod 2>nul || git checkout -b prod origin/prod
git pull origin prod

if errorlevel 1 (
    echo ERROR: Git operations failed!
    pause
    exit /b 1
)

echo Running AD Account Custodian...
powershell.exe -ExecutionPolicy Bypass -File "AD-Account-Custodian.ps1"

echo Completed with exit code: %errorlevel%
