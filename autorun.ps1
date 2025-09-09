# AD Account Custodian - PowerShell AutoRunner
# This script pulls the latest prod branch and runs the main orchestrator

param(
    [string]$Branch = "prod",
    [switch]$TestMode = $false,
    [switch]$Verbose = $false
)

# Set error action preference
$ErrorActionPreference = "Stop"

# Script variables
$ScriptName = "AD Account Custodian AutoRunner"
$MainScript = "AD-Account-Custodian.ps1"
$ConfigFile = "AD-Account-Custodian.yaml"
$LogDir = "Logs"
$LogFile = Join-Path $LogDir "autorun_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Create logs directory if it doesn't exist
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

# Logging function
function Write-AutoLog {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Write to log file
    Add-Content -Path $LogFile -Value $logEntry -Encoding ASCII
    
    # Write to console with color
    switch ($Level) {
        "INFO" { 
            if ($Verbose) { Write-Host $logEntry -ForegroundColor Green }
        }
        "WARN" { Write-Host $logEntry -ForegroundColor Yellow }
        "ERROR" { Write-Host $logEntry -ForegroundColor Red }
    }
}

try {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host $ScriptName -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host

    Write-AutoLog "Starting $ScriptName" -Level "INFO"
    Write-AutoLog "Current Directory: $(Get-Location)" -Level "INFO"
    Write-AutoLog "Target Branch: $Branch" -Level "INFO"
    Write-AutoLog "Test Mode: $TestMode" -Level "INFO"
    Write-AutoLog "Log File: $LogFile" -Level "INFO"

    # Validate environment
    Write-AutoLog "Validating environment..." -Level "INFO"
    
    if (-not (Test-Path ".git")) {
        throw "Not in a git repository! Please ensure this script is run from the ad-account-custodian repository directory."
    }

    # Check if git is available
    try {
        $gitVersion = git --version
        Write-AutoLog "Git version: $gitVersion" -Level "INFO"
    }
    catch {
        throw "Git is not installed or not in PATH!"
    }

    Write-AutoLog "Environment validation completed successfully" -Level "INFO"

    # Git operations
    Write-AutoLog "Starting git operations..." -Level "INFO"
    Write-Host "Fetching latest changes from remote..." -ForegroundColor Yellow

    git fetch origin
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to fetch from remote repository!"
    }
    Write-AutoLog "Successfully fetched from remote" -Level "INFO"

    # Check if target branch exists locally
    git rev-parse --verify $Branch 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Setting up local $Branch branch..." -ForegroundColor Yellow
        Write-AutoLog "Creating local $Branch branch..." -Level "INFO"
        
        git checkout -b $Branch origin/$Branch
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to create local $Branch branch! Please ensure the $Branch branch exists on the remote repository."
        }
    }
    else {
        Write-Host "Switching to $Branch branch..." -ForegroundColor Yellow
        Write-AutoLog "Switching to $Branch branch..." -Level "INFO"
        
        git checkout $Branch
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to switch to $Branch branch!"
        }
        
        Write-Host "Pulling latest changes..." -ForegroundColor Yellow
        Write-AutoLog "Pulling latest changes..." -Level "INFO"
        
        git pull origin $Branch
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to pull latest changes! Please resolve any merge conflicts manually."
        }
    }

    # Get current commit info
    $currentBranch = git branch --show-current
    $currentCommit = git rev-parse --short HEAD
    $commitMessage = git log -1 --pretty=format:"%s"

    Write-AutoLog "Git operations completed successfully" -Level "INFO"
    Write-AutoLog "Current branch: $currentBranch" -Level "INFO"
    Write-AutoLog "Current commit: $currentCommit" -Level "INFO"
    Write-AutoLog "Commit message: $commitMessage" -Level "INFO"

    Write-Host
    Write-Host "Git operations completed successfully!" -ForegroundColor Green
    Write-Host "Current branch: $currentBranch" -ForegroundColor Cyan
    Write-Host "Current commit: $currentCommit" -ForegroundColor Cyan
    Write-Host "Commit message: $commitMessage" -ForegroundColor Gray
    Write-Host

    # Validate required files
    Write-AutoLog "Validating required files..." -Level "INFO"

    if (-not (Test-Path $MainScript)) {
        throw "Main orchestrator script not found: $MainScript"
    }

    if (-not (Test-Path $ConfigFile)) {
        throw "Configuration file not found: $ConfigFile"
    }

    Write-AutoLog "File validation completed successfully" -Level "INFO"

    # Execute the main script
    Write-AutoLog "Starting AD Account Custodian execution..." -Level "INFO"
    Write-Host "Starting AD Account Custodian..." -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host

    # Build arguments for the main script
    $scriptArgs = @()
    if ($TestMode) {
        $scriptArgs += "-TestMode"
    }

    # Execute the main script
    if ($scriptArgs.Count -gt 0) {
        & ".\$MainScript" @scriptArgs
    }
    else {
        & ".\$MainScript"
    }

    $scriptExitCode = $LASTEXITCODE

    Write-AutoLog "AD Account Custodian execution completed with exit code: $scriptExitCode" -Level "INFO"

    Write-Host
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "AD Account Custodian execution completed" -ForegroundColor Cyan
    Write-Host "Exit Code: $scriptExitCode" -ForegroundColor $(if ($scriptExitCode -eq 0) { "Green" } else { "Red" })
    Write-Host "End Time: $(Get-Date)" -ForegroundColor Gray
    Write-Host "========================================" -ForegroundColor Cyan

    if ($scriptExitCode -eq 0) {
        Write-AutoLog "Execution completed successfully" -Level "INFO"
        Write-Host "Execution completed successfully!" -ForegroundColor Green
    }
    else {
        Write-AutoLog "Execution failed with exit code: $scriptExitCode" -Level "ERROR"
        Write-Host "Script execution failed. Check the logs for details." -ForegroundColor Red
        Write-Host "Log file: $LogFile" -ForegroundColor Yellow
    }

    Write-AutoLog "AutoRunner session ended" -Level "INFO"
    exit $scriptExitCode
}
catch {
    $errorMessage = $_.Exception.Message
    Write-AutoLog "FATAL ERROR: $errorMessage" -Level "ERROR"
    Write-Host "FATAL ERROR: $errorMessage" -ForegroundColor Red
    Write-Host "Log file: $LogFile" -ForegroundColor Yellow
    Write-AutoLog "AutoRunner session ended with error" -Level "ERROR"
    exit 1
}
