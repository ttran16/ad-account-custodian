<#
.SYNOPSIS
    AD Account Custodian Module - Complete toolkit for managing Active Directory accounts

.DESCRIPTION
    This module contains all necessary functions for AD account management:
    - Module management and installation utilities
    - Logging functions with file and console output
    - Password reset enforcement for accounts with old passwords
    - Account disabling based on inactivity thresholds
    - Common utility functions for AD account management

.NOTES
    Requires: ActiveDirectory PowerShell module
    Auto-installs: powershell-yaml module if needed
#>

#region Module Management Functions

function Import-RequiredModules {
    <#
    .SYNOPSIS
        Imports required modules, installing them if necessary
    
    .PARAMETER Modules
        Array of module names to import/install
    
    .EXAMPLE
        Import-RequiredModules -Modules @('ActiveDirectory', 'powershell-yaml')
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Modules
    )
    
    foreach ($moduleName in $Modules) {
        switch ($moduleName) {
            'ActiveDirectory' {
                try {
                    Import-Module ActiveDirectory -ErrorAction Stop
                    Write-Host "ActiveDirectory module imported successfully." -ForegroundColor Green
                }
                catch {
                    Write-Error "ActiveDirectory module not available. Please install RSAT tools or run on a domain controller."
                    throw
                }
            }
            
            'powershell-yaml' {
                try {
                    Import-Module powershell-yaml -ErrorAction Stop
                    Write-Host "powershell-yaml module imported successfully." -ForegroundColor Green
                }
                catch {
                    Write-Host "powershell-yaml module not found. Installing..." -ForegroundColor Yellow
                    try {
                        Install-PowerShellYaml
                        Import-Module powershell-yaml -ErrorAction Stop
                        Write-Host "powershell-yaml module installed and imported successfully." -ForegroundColor Green
                    }
                    catch {
                        Write-Error "Failed to install or import powershell-yaml module: $_"
                        Write-Error "Please run 'Install-Module powershell-yaml' manually or run this script as administrator."
                        throw
                    }
                }
            }
            
            default {
                try {
                    Import-Module $moduleName -ErrorAction Stop
                    Write-Host "$moduleName module imported successfully." -ForegroundColor Green
                }
                catch {
                    Write-Error "Failed to import module: $moduleName. Error: $_"
                    throw
                }
            }
        }
    }
}

function Install-PowerShellYaml {
    <#
    .SYNOPSIS
        Installs the powershell-yaml module with appropriate scope
    #>
    [CmdletBinding()]
    param()
    
    # Check if running as administrator
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if ($isAdmin) {
        # Install for all users if running as admin
        Install-Module -Name powershell-yaml -Force -AllowClobber -Scope AllUsers
        Write-Host "Installed powershell-yaml module for all users." -ForegroundColor Green
    } else {
        # Install for current user only
        Install-Module -Name powershell-yaml -Force -AllowClobber -Scope CurrentUser
        Write-Host "Installed powershell-yaml module for current user." -ForegroundColor Green
    }
}

#endregion

#region Logging Functions

function Write-Log {
    <#
    .SYNOPSIS
        Writes log messages to console and optionally to a file
    
    .PARAMETER Message
        The message to log
    
    .PARAMETER Level
        The log level (INFO, WARN, ERROR)
    
    .PARAMETER LogPath
        Optional path to log file
    
    .EXAMPLE
        Write-Log "Process started" -LogPath "C:\Logs\script.log"
        
    .EXAMPLE
        Write-Log "Warning message" -Level "WARN" -LogPath "C:\Logs\script.log"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("INFO", "WARN", "ERROR", "DEBUG")]
        [string]$Level = "INFO",
        
        [Parameter(Mandatory = $false)]
        [string]$LogPath
    )
    
    # Clean message of any potential Unicode characters
    $CleanMessage = $Message -replace '[^\x20-\x7E\x09\x0A\x0D]', '?'
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $CleanMessage"
    
    # Write to console with appropriate colors
    switch ($Level) {
        "ERROR" { Write-Host $logEntry -ForegroundColor Red }
        "WARN"  { Write-Host $logEntry -ForegroundColor Yellow }
        "INFO"  { Write-Host $logEntry -ForegroundColor Green }
        "DEBUG" { Write-Host $logEntry -ForegroundColor Cyan }
        default { Write-Host $logEntry }
    }
    
    # Write to log file if path provided
    if ($LogPath) {
        try {
            # Ensure log directory exists
            $logDir = Split-Path $LogPath -Parent
            if ($logDir -and !(Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            # Use ASCII encoding for log files
            Add-Content -Path $LogPath -Value $logEntry -Encoding ASCII
        }
        catch {
            Write-Warning "Failed to write to log file: $_"
        }
    }
}

function Initialize-Logging {
    <#
    .SYNOPSIS
        Initializes a log file with header information
    
    .PARAMETER LogPath
        Path to the log file
    
    .PARAMETER ScriptName
        Name of the script being logged
    
    .EXAMPLE
        Initialize-Logging -LogPath "C:\Logs\script.log" -ScriptName "AD-Account-Custodian"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LogPath,
        
        [Parameter(Mandatory = $true)]
        [string]$ScriptName
    )
    
    $separator = "=" * 80
    $header = @"
$separator
$ScriptName - Started at $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
PowerShell Version: $($PSVersionTable.PSVersion)
User: $env:USERNAME
Computer: $env:COMPUTERNAME
$separator
"@
    
    try {
        # Ensure log directory exists
        $logDir = Split-Path $LogPath -Parent
        if ($logDir -and !(Test-Path $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        }
        
        # Write header to log file
        Add-Content -Path $LogPath -Value $header -Encoding ASCII
        Write-Host "Logging initialized: $LogPath" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to initialize log file: $_"
    }
}

function Write-LogSeparator {
    <#
    .SYNOPSIS
        Writes a separator line to the log
    
    .PARAMETER LogPath
        Path to the log file
    
    .PARAMETER Message
        Optional message to include with separator
    
    .EXAMPLE
        Write-LogSeparator -LogPath "C:\Logs\script.log" -Message "Processing Complete"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$LogPath,
        
        [Parameter(Mandatory = $false)]
        [string]$Message
    )
    
    # Use standard ASCII dash characters only
    $separator = "-" * 60
    if ($Message) {
        $separatorLine = "$separator $Message $separator"
    } else {
        $separatorLine = $separator
    }
    
    Write-Log $separatorLine -LogPath $LogPath
}

#endregion

#region Utility Functions

function Test-ExcludedUser {
    <#
    .SYNOPSIS
        Checks if a user should be excluded from processing
    
    .PARAMETER Username
        The username to check
    
    .PARAMETER ExcludedUsers
        Array of excluded user patterns (supports wildcards)
    
    .RETURNS
        Boolean indicating if user should be excluded
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Username,
        
        [Parameter(Mandatory = $false)]
        [array]$ExcludedUsers = @()
    )
    
    # Return false if no exclusions defined
    if (-not $ExcludedUsers -or $ExcludedUsers.Count -eq 0) {
        return $false
    }
    
    foreach ($excludedUser in $ExcludedUsers) {
        if ([string]::IsNullOrWhiteSpace($excludedUser)) {
            continue
        }
        if ($Username -like $excludedUser) {
            return $true
        }
    }
    return $false
}

function Test-ServiceAccount {
    <#
    .SYNOPSIS
        Checks if an account appears to be a service account
    
    .PARAMETER Username
        Username to check
    
    .PARAMETER Config
        Configuration object containing service account patterns
    
    .RETURNS
        Boolean indicating if account appears to be a service account
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Username,
        
        [Parameter(Mandatory = $false)]
        [PSObject]$Config
    )
    
    try {
        # Common service account patterns (all lowercase for consistent matching)
        $servicePatterns = @(
            "*service*",
            "*svc*", 
            "*admin*",
            "*system*",
            "*backup*",
            "*sql*"
        )
        
        # Get clean values for comparison
        $samAccountName = $Username.ToLower()
        
        foreach ($pattern in $servicePatterns) {
            if ($samAccountName -like $pattern) {
                return $true
            }
        }
        
        return $false
    }
    catch {
        Write-Warning "Error evaluating service account status for user: $_"
        return $false
    }
}

function Invoke-PasswordReset {
    <#
    .SYNOPSIS
        Sets password reset flags for accounts with old passwords
    
    .PARAMETER OU
        Organizational unit configuration object
    
    .PARAMETER Config
        Global configuration object
    
    .RETURNS
        Number of accounts modified
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [PSObject]$OU,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [PSObject]$Config
    )
    
    try {
        $modifiedCount = 0
        
        # Validate required OU properties
        if (-not $OU.DistinguishedName -or -not $OU.Description) {
            Write-Log "ERROR: OU missing required properties (DistinguishedName or Description)" -Level "ERROR" -LogPath $Config.LogFile
            return 0
        }
        
        Write-Log "Processing password reset for OU: $($OU.Description)" -LogPath $Config.LogFile
        Write-Log "Password age threshold: $($OU.PasswordAgeThresholdDays) days" -LogPath $Config.LogFile
        
        # Calculate cutoff date
        $cutoffDate = (Get-Date).AddDays(-$OU.PasswordAgeThresholdDays)
        
        # Build search parameters - use simple filter and handle complex logic client-side
        $searchParams = @{
            SearchBase = $OU.DistinguishedName
            Filter = "*"
            Properties = @('SamAccountName', 'PasswordLastSet', 'PasswordNeverExpires', 'whenCreated', 'PasswordExpired', 'DisplayName')
            ErrorAction = 'Stop'
        }
        
        if ($OU.IncludeSubOUs) {
            $searchParams.SearchScope = "Subtree"
        } else {
            $searchParams.SearchScope = "OneLevel"
        }
        
        # Get all users from the OU and apply client-side filtering (based on your working command)
        $allUsers = Get-ADUser @searchParams
        
        # Filter for users needing password reset (based on your working PowerShell command)
        $usersNeedingReset = $allUsers | Where-Object { 
            $_.whenCreated -lt $cutoffDate -and 
            ($_.PasswordLastSet -eq $null -or $_.PasswordLastSet -lt $cutoffDate) -and 
            $_.PasswordExpired -eq $false 
        }
        
        $totalUserCount = $usersNeedingReset.Count
        Write-Log "Found $totalUserCount users requiring password reset evaluation" -LogPath $Config.LogFile
        
        # Apply user limit if configured
        $maxUsers = if ($Config.MaxUsersPerRun -and $Config.MaxUsersPerRun -gt 0) { 
            $Config.MaxUsersPerRun 
        } else { 
            $null
        }
        
        # Get users with limit applied
        if ($maxUsers -and $totalUserCount -gt $maxUsers) {
            $users = $usersNeedingReset | Select-Object -First $maxUsers
            Write-Log "Processing first $maxUsers of $totalUserCount users (MaxUsersPerRun: $($Config.MaxUsersPerRun))" -LogPath $Config.LogFile
            Write-Log "Remaining users for future runs: $($totalUserCount - $maxUsers)" -LogPath $Config.LogFile
        } else {
            $users = $usersNeedingReset
            Write-Log "Processing all $totalUserCount users" -LogPath $Config.LogFile
        }
        
        foreach ($user in $users) {
            # Skip if user object is invalid
            if (-not $user.SamAccountName) {
                Write-Log "WARNING: Skipping user with invalid SamAccountName" -Level "WARN" -LogPath $Config.LogFile
                continue
            }
            
            # Check exclusions
            if (Test-ExcludedUser -Username $user.SamAccountName -ExcludedUsers $OU.ExcludedUsers) {
                Write-Log "Skipping excluded user: $($user.SamAccountName)" -LogPath $Config.LogFile
                continue
            }
            
            if ($user.PasswordNeverExpires) {
                Write-Log "Skipping user with PasswordNeverExpires: $($user.SamAccountName)" -LogPath $Config.LogFile
                continue
            }
            
            $passwordAge = if ($user.PasswordLastSet) { 
                [math]::Round(((Get-Date) - $user.PasswordLastSet).TotalDays)
            } else { 
                "Never set"
            }
            
            if ($Config.TestMode) {
                Write-Log "TEST MODE: Would set password reset for: $($user.SamAccountName) (Password age: $passwordAge days)" -LogPath $Config.LogFile
                $modifiedCount++
            } else {
                try {
                    Set-ADUser -Identity $user.SamAccountName -ChangePasswordAtLogon $true -ErrorAction Stop
                    Write-Log "Set password reset for: $($user.SamAccountName) (Password age: $passwordAge days)" -LogPath $Config.LogFile
                    $modifiedCount++
                }
                catch {
                    Write-Log "ERROR: Failed to set password reset for $($user.SamAccountName): $_" -Level "ERROR" -LogPath $Config.LogFile
                }
            }
        }
        
        Write-Log "Password reset processing complete: $modifiedCount accounts processed" -LogPath $Config.LogFile
        return $modifiedCount
    }
    catch {
        Write-Log "ERROR: Password reset processing failed: $_" -Level "ERROR" -LogPath $Config.LogFile
        return 0
    }
}

function Invoke-InactivityDisable {
    <#
    .SYNOPSIS
        Disables accounts that have been inactive for too long
    
    .PARAMETER OU
        Organizational unit configuration object
    
    .PARAMETER Config
        Global configuration object
    
    .RETURNS
        Number of accounts disabled
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [PSObject]$OU,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [PSObject]$Config
    )
    
    try {
        $disabledCount = 0
        
        # Validate required OU properties
        if (-not $OU.DistinguishedName -or -not $OU.Description) {
            Write-Log "ERROR: OU missing required properties (DistinguishedName or Description)" -Level "ERROR" -LogPath $Config.LogFile
            return 0
        }
        
        Write-Log "Processing inactivity disable for OU: $($OU.Description)" -LogPath $Config.LogFile
        Write-Log "Inactivity threshold: $($OU.InactivityThresholdDays) days" -LogPath $Config.LogFile
        
        # Calculate cutoff date for last logon
        $inactivityCutoff = (Get-Date).AddDays(-$OU.InactivityThresholdDays)
        
        # Build search parameters for enabled accounts
        $searchParams = @{
            SearchBase = $OU.DistinguishedName
            Filter = "Enabled -eq `$true"
            Properties = @('SamAccountName', 'LastLogonDate', 'whenCreated', 'Description', 'DistinguishedName')
            ErrorAction = 'Stop'
        }
        
        if ($OU.IncludeSubOUs) {
            $searchParams.SearchScope = "Subtree"
        } else {
            $searchParams.SearchScope = "OneLevel"
        }
        
        # Get all enabled users
        $users = Get-ADUser @searchParams
        
        # Filter for inactive users
        $inactiveUsers = $users | Where-Object {
            # Account must be older than inactivity threshold (to avoid disabling new accounts)
            $accountAge = $_.whenCreated -and $_.whenCreated -lt $inactivityCutoff
            
            # Last logon must be older than threshold OR never logged on
            $lastLogonOld = (-not $_.LastLogonDate) -or ($_.LastLogonDate -lt $inactivityCutoff)
            
            $accountAge -and $lastLogonOld
        }
        
        $totalInactiveCount = $inactiveUsers.Count
        Write-Log "Found $totalInactiveCount inactive users for potential disabling" -LogPath $Config.LogFile
        
        # Apply user limit if configured
        $maxUsers = if ($Config.MaxUsersPerRun -and $Config.MaxUsersPerRun -gt 0) { 
            $Config.MaxUsersPerRun 
        } else { 
            $null
        }
        
        if ($maxUsers -and $totalInactiveCount -gt $maxUsers) {
            $inactiveUsers = $inactiveUsers | Select-Object -First $maxUsers
            Write-Log "Processing first $maxUsers of $totalInactiveCount inactive users (MaxUsersPerRun: $($Config.MaxUsersPerRun))" -LogPath $Config.LogFile
            Write-Log "Remaining inactive users for future runs: $($totalInactiveCount - $maxUsers)" -LogPath $Config.LogFile
        } else {
            Write-Log "Processing all $totalInactiveCount inactive users" -LogPath $Config.LogFile
        }
        
        foreach ($user in $inactiveUsers) {
            # Skip if user object is invalid
            if (-not $user.SamAccountName) {
                Write-Log "WARNING: Skipping user with invalid SamAccountName" -Level "WARN" -LogPath $Config.LogFile
                continue
            }
            
            # Check exclusions
            if (Test-ExcludedUser -Username $user.SamAccountName -ExcludedUsers $OU.ExcludedUsers) {
                Write-Log "Skipping excluded user: $($user.SamAccountName)" -LogPath $Config.LogFile
                continue
            }
            
            # Skip service accounts if configured
            if ($OU.ExcludeServiceAccounts -and (Test-ServiceAccount -Username $user.SamAccountName -Config $Config)) {
                Write-Log "Skipping service account: $($user.SamAccountName)" -LogPath $Config.LogFile
                continue
            }
            
            $lastLogon = if ($user.LastLogonDate) {
                $user.LastLogonDate.ToString("yyyy-MM-dd")
            } else {
                "Never"
            }
            
            $inactiveDays = if ($user.LastLogonDate) {
                [math]::Round(((Get-Date) - $user.LastLogonDate).TotalDays)
            } else {
                [math]::Round(((Get-Date) - $user.whenCreated).TotalDays)
            }
            
            if ($Config.TestMode) {
                Write-Log "TEST MODE: Would disable inactive user: $($user.SamAccountName) (Last logon: $lastLogon, Inactive: $inactiveDays days)" -LogPath $Config.LogFile
                $disabledCount++
            } else {
                try {
                    # Disable the account
                    Disable-ADAccount -Identity $user.SamAccountName -ErrorAction Stop
                    
                    # Add disable note if configured
                    if ($OU.AddDisableNote) {
                        $disableNote = "Disabled on $(Get-Date -Format 'yyyy-MM-dd') due to inactivity ($inactiveDays days). Last logon: $lastLogon"
                        
                        # Clean existing description for ASCII encoding
                        $currentDescription = if ($user.Description) { 
                            [System.Text.Encoding]::ASCII.GetString([System.Text.Encoding]::ASCII.GetBytes($user.Description))
                        } else { 
                            ""
                        }
                        
                        $newDescription = if ($currentDescription) {
                            "$currentDescription | $disableNote"
                        } else {
                            $disableNote
                        }
                        
                        # Ensure description is ASCII-safe
                        $cleanDescription = [System.Text.Encoding]::ASCII.GetString([System.Text.Encoding]::ASCII.GetBytes($newDescription))
                        Set-ADUser -Identity $user.SamAccountName -Description $cleanDescription -ErrorAction Stop
                    }
                    
                    # Move to disabled OU if configured
                    if ($OU.DisabledAccountsOU) {
                        try {
                            Move-ADObject -Identity $user.DistinguishedName -TargetPath $OU.DisabledAccountsOU -ErrorAction Stop
                            Write-Log "Disabled and moved user: $($user.SamAccountName) to $($OU.DisabledAccountsOU)" -LogPath $Config.LogFile
                        }
                        catch {
                            Write-Log "Disabled user $($user.SamAccountName) but failed to move: $_" -Level "WARN" -LogPath $Config.LogFile
                        }
                    } else {
                        Write-Log "Disabled inactive user: $($user.SamAccountName) (Inactive: $inactiveDays days)" -LogPath $Config.LogFile
                    }
                    
                    $disabledCount++
                }
                catch {
                    Write-Log "ERROR: Failed to disable user $($user.SamAccountName): $_" -Level "ERROR" -LogPath $Config.LogFile
                }
            }
        }
        
        Write-Log "Inactivity disable processing complete: $disabledCount accounts processed" -LogPath $Config.LogFile
        return $disabledCount
    }
    catch {
        Write-Log "ERROR: Inactivity disable processing failed: $_" -Level "ERROR" -LogPath $Config.LogFile
        return 0
    }
}

#endregion

# Export all public functions
Export-ModuleMember -Function Import-RequiredModules, Install-PowerShellYaml, Write-Log, Initialize-Logging, Write-LogSeparator, Test-ExcludedUser, Test-ServiceAccount, Invoke-PasswordReset, Invoke-InactivityDisable
