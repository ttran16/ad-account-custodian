@echo off
REM AD Account Custodian - Advanced Automated Runner
REM This script provides comprehensive automation with logging and error handling

setlocal enabledelayedexpansion

REM Set up variables
set SCRIPT_NAME=AD Account Custodian AutoRunner
set LOG_DIR=Logs
set LOG_FILE=%LOG_DIR%\autorun_%DATE:~-4,4%%DATE:~-10,2%%DATE:~-7,2%_%TIME:~0,2%%TIME:~3,2%%TIME:~6,2%.log
set LOG_FILE=%LOG_FILE: =0%
set MAIN_SCRIPT=AD-Account-Custodian.ps1
set CONFIG_FILE=AD-Account-Custodian.yaml
set TARGET_BRANCH=prod

echo ========================================
echo %SCRIPT_NAME%
echo ========================================
echo.

REM Create logs directory if it doesn't exist
if not exist "%LOG_DIR%" (
    mkdir "%LOG_DIR%"
    if errorlevel 1 (
        echo ERROR: Failed to create logs directory!
        pause
        exit /b 1
    )
)

REM Function to log messages (simulated with echo and redirection)
call :LogMessage "INFO" "Starting %SCRIPT_NAME%"
call :LogMessage "INFO" "Current Directory: %CD%"
call :LogMessage "INFO" "Start Time: %DATE% %TIME%"
call :LogMessage "INFO" "Target Branch: %TARGET_BRANCH%"
call :LogMessage "INFO" "Log File: %LOG_FILE%"

REM Change to the script directory
cd /d "%~dp0"

REM Validate environment
call :LogMessage "INFO" "Validating environment..."

REM Check if we're in a git repository
if not exist ".git" (
    call :LogMessage "ERROR" "Not in a git repository!"
    echo ERROR: Not in a git repository!
    echo Please ensure this script is run from the ad-account-custodian repository directory.
    pause
    exit /b 1
)

REM Check if git is available
git --version >nul 2>&1
if errorlevel 1 (
    call :LogMessage "ERROR" "Git is not installed or not in PATH!"
    echo ERROR: Git is not installed or not in PATH!
    pause
    exit /b 1
)

REM Check if PowerShell is available
powershell.exe -Command "Get-Host" >nul 2>&1
if errorlevel 1 (
    call :LogMessage "ERROR" "PowerShell is not available!"
    echo ERROR: PowerShell is not available!
    pause
    exit /b 1
)

call :LogMessage "INFO" "Environment validation completed successfully"

REM Git operations
call :LogMessage "INFO" "Starting git operations..."

echo Fetching latest changes from remote...
call :LogMessage "INFO" "Fetching from remote repository..."
git fetch origin
if errorlevel 1 (
    call :LogMessage "ERROR" "Failed to fetch from remote repository!"
    echo ERROR: Failed to fetch from remote repository!
    echo Please check your network connection and git configuration.
    pause
    exit /b 1
)

REM Check if target branch exists locally
call :LogMessage "INFO" "Checking for local %TARGET_BRANCH% branch..."
git rev-parse --verify %TARGET_BRANCH% >nul 2>&1
if errorlevel 1 (
    call :LogMessage "INFO" "Creating local %TARGET_BRANCH% branch..."
    echo Setting up local %TARGET_BRANCH% branch...
    git checkout -b %TARGET_BRANCH% origin/%TARGET_BRANCH%
    if errorlevel 1 (
        call :LogMessage "ERROR" "Failed to create local %TARGET_BRANCH% branch!"
        echo ERROR: Failed to create local %TARGET_BRANCH% branch!
        echo Please ensure the %TARGET_BRANCH% branch exists on the remote repository.
        pause
        exit /b 1
    )
) else (
    call :LogMessage "INFO" "Switching to %TARGET_BRANCH% branch..."
    echo Switching to %TARGET_BRANCH% branch...
    git checkout %TARGET_BRANCH%
    if errorlevel 1 (
        call :LogMessage "ERROR" "Failed to switch to %TARGET_BRANCH% branch!"
        echo ERROR: Failed to switch to %TARGET_BRANCH% branch!
        pause
        exit /b 1
    )
    
    call :LogMessage "INFO" "Pulling latest changes..."
    echo Pulling latest changes...
    git pull origin %TARGET_BRANCH%
    if errorlevel 1 (
        call :LogMessage "ERROR" "Failed to pull latest changes!"
        echo ERROR: Failed to pull latest changes!
        echo Please resolve any merge conflicts manually.
        pause
        exit /b 1
    )
)

REM Get current commit info
for /f "tokens=*" %%i in ('git rev-parse --short HEAD') do set CURRENT_COMMIT=%%i
for /f "tokens=*" %%i in ('git branch --show-current') do set CURRENT_BRANCH=%%i

call :LogMessage "INFO" "Git operations completed successfully"
call :LogMessage "INFO" "Current branch: %CURRENT_BRANCH%"
call :LogMessage "INFO" "Current commit: %CURRENT_COMMIT%"

echo.
echo Git operations completed successfully!
echo Current branch: %CURRENT_BRANCH%
echo Current commit: %CURRENT_COMMIT%
echo.

REM Validate required files
call :LogMessage "INFO" "Validating required files..."

if not exist "%MAIN_SCRIPT%" (
    call :LogMessage "ERROR" "Main orchestrator script not found: %MAIN_SCRIPT%"
    echo ERROR: Main orchestrator script not found!
    echo Expected: %MAIN_SCRIPT%
    echo Please ensure the script exists in the repository.
    pause
    exit /b 1
)

if not exist "%CONFIG_FILE%" (
    call :LogMessage "ERROR" "Configuration file not found: %CONFIG_FILE%"
    echo ERROR: Configuration file not found!
    echo Expected: %CONFIG_FILE%
    echo Please ensure the configuration file exists in the repository.
    pause
    exit /b 1
)

call :LogMessage "INFO" "File validation completed successfully"

REM Execute the main script
call :LogMessage "INFO" "Starting AD Account Custodian execution..."
echo Starting AD Account Custodian...
echo ========================================
echo.

powershell.exe -ExecutionPolicy Bypass -File "%MAIN_SCRIPT%"
set SCRIPT_EXIT_CODE=!errorlevel!

call :LogMessage "INFO" "AD Account Custodian execution completed with exit code: !SCRIPT_EXIT_CODE!"

echo.
echo ========================================
echo AD Account Custodian execution completed
echo Exit Code: !SCRIPT_EXIT_CODE!
echo End Time: %DATE% %TIME%
echo ========================================

if !SCRIPT_EXIT_CODE! equ 0 (
    call :LogMessage "INFO" "Execution completed successfully"
    echo Execution completed successfully!
) else (
    call :LogMessage "ERROR" "Execution failed with exit code: !SCRIPT_EXIT_CODE!"
    echo.
    echo Script execution failed. Check the logs for details.
    echo Log file: %LOG_FILE%
    echo Press any key to continue...
    pause >nul
)

call :LogMessage "INFO" "AutoRunner session ended"
exit /b !SCRIPT_EXIT_CODE!

REM Function to log messages
:LogMessage
set LEVEL=%~1
set MESSAGE=%~2
set TIMESTAMP=%DATE% %TIME%
echo [%TIMESTAMP%] [%LEVEL%] %MESSAGE% >> "%LOG_FILE%"
if /i "%LEVEL%"=="ERROR" (
    echo [%TIMESTAMP%] [%LEVEL%] %MESSAGE%
)
goto :eof
