#Requires -Module ActiveDirectory
<#
.SYNOPSIS
    AD Account Custodian Orchestrator - Manages Active Directory account lifecycle

.DESCRIPTION
    This orchestrator script coordinates multiple AD account management functions:
    - Password reset enforcement for accounts with old passwords
    - Account disabling based on inactivity thresholds
    
    Each function can be enabled/disabled per OU by setting thresholds to 0.

.PARAMETER ConfigFile
    Path to the YAML configuration file. Defaults to AD-Account-Custodian.yaml

.EXAMPLE
    .\AD-Account-Custodian.ps1
    
.EXAMPLE
    .\AD-Account-Custodian.ps1 -ConfigFile "C:\Config\MyConfig.yaml"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigFile = ".\AD-Account-Custodian.yaml"
)

# Get script path and import the AD Account Custodian module
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path

# Import the AD Account Custodian module (contains all necessary functions)
try {
    Import-Module "$scriptPath\Modules\ADAccountCustodian.psm1" -Force
    
    # Import required external modules
    Import-RequiredModules -Modules @('ActiveDirectory', 'powershell-yaml')
}
catch {
    Write-Error "Failed to import required modules: $_"
    exit 1
}

# Main orchestrator execution
try {
    # Check if configuration file exists
    if (!(Test-Path $ConfigFile)) {
        throw "Configuration file not found: $ConfigFile"
    }
    
    # Load configuration
    $configContent = Get-Content $ConfigFile -Raw
    $config = ConvertFrom-Yaml $configContent
    
    # Initialize logging
    Initialize-Logging -LogPath $config.LogFile -ScriptName "AD-Account-Custodian"
    
    Write-Log "Starting AD Account Custodian orchestrator" -LogPath $config.LogFile
    Write-Log "Configuration loaded from: $ConfigFile" -LogPath $config.LogFile
    Write-Log "Test Mode: $($config.TestMode)" -LogPath $config.LogFile
    
    # Initialize counters
    $totalPasswordResets = 0
    $totalDisabled = 0
    $processedOUs = 0
    
    # Process each organizational unit
    foreach ($ou in $config.OrganizationalUnits) {
        Write-LogSeparator -LogPath $config.LogFile -Message "Processing OU: $($ou.Description)"
        Write-Log "OU: $($ou.DistinguishedName)" -LogPath $config.LogFile
        
        # Determine which functions are enabled
        $passwordResetEnabled = $ou.PasswordAgeThresholdDays -gt 0
        $inactivityDisableEnabled = $ou.InactivityThresholdDays -gt 0
        
        Write-Log "Password reset enabled: $passwordResetEnabled (threshold: $($ou.PasswordAgeThresholdDays) days)" -LogPath $config.LogFile
        Write-Log "Inactivity disable enabled: $inactivityDisableEnabled (threshold: $($ou.InactivityThresholdDays) days)" -LogPath $config.LogFile
        
        # Skip OU if both functions are disabled
        if (-not $passwordResetEnabled -and -not $inactivityDisableEnabled) {
            Write-Log "Both functions disabled for this OU - skipping" -LogPath $config.LogFile
            continue
        }
        
        $processedOUs++
        
        try {
            # Execute password reset function if enabled
            if ($passwordResetEnabled) {
                Write-Log "Executing password reset function..." -LogPath $config.LogFile
                $passwordResetCount = Invoke-PasswordReset -OU $ou -Config $config
                $totalPasswordResets += $passwordResetCount
                Write-Log "Password reset function completed: $passwordResetCount accounts processed" -LogPath $config.LogFile
            }
            
            # Execute inactivity disable function if enabled  
            if ($inactivityDisableEnabled) {
                Write-Log "Executing inactivity disable function..." -LogPath $config.LogFile
                $disabledCount = Invoke-InactivityDisable -OU $ou -Config $config
                $totalDisabled += $disabledCount
                Write-Log "Inactivity disable function completed: $disabledCount accounts processed" -LogPath $config.LogFile
            }
            
            Write-Log "OU processing completed successfully" -LogPath $config.LogFile
        }
        catch {
            Write-Log "ERROR: Failed to process OU $($ou.DistinguishedName): $_" -Level "ERROR" -LogPath $config.LogFile
            continue
        }
    }
    
    # Final summary
    Write-LogSeparator -LogPath $config.LogFile -Message "Orchestrator Summary"
    Write-Log "Processed $processedOUs organizational units" -LogPath $config.LogFile
    
    if ($config.TestMode) {
        Write-Log "TEST MODE RESULTS:" -LogPath $config.LogFile
        Write-Log "  - Would set password reset for: $totalPasswordResets users" -LogPath $config.LogFile
        Write-Log "  - Would disable for inactivity: $totalDisabled users" -LogPath $config.LogFile
    } else {
        Write-Log "PRODUCTION RESULTS:" -LogPath $config.LogFile
        Write-Log "  - Password reset set for: $totalPasswordResets users" -LogPath $config.LogFile
        Write-Log "  - Disabled for inactivity: $totalDisabled users" -LogPath $config.LogFile
    }
    
    Write-Log "AD Account Custodian orchestrator completed successfully" -LogPath $config.LogFile
}
catch {
    Write-Log "FATAL ERROR in orchestrator: $_" -Level "ERROR" -LogPath $config.LogFile
    exit 1
}
finally {
    # Clean up - remove the imported module
    Remove-Module ADAccountCustodian -ErrorAction SilentlyContinue
}
