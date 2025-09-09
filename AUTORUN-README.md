# AD Account Custodian - AutoRunner

Simple batch script that pulls the latest production code and executes the AD Account Custodian.

## autorun.bat

**Purpose**: Minimal batch script for automated execution
**Features**:
- Pulls latest `prod` branch
- Runs AD-Account-Custodian.ps1
- Basic error handling

**Usage**:
```cmd
autorun.bat
```

## What it does:

1. Fetches latest changes from remote repository
2. Switches to `prod` branch (creates if needed)
3. Pulls latest changes
4. Runs the AD Account Custodian PowerShell script
5. Shows completion status

## Prerequisites

1. **Git**: Must be installed and available in PATH
2. **PowerShell**: Required for script execution  
3. **Repository Setup**: Must be run from the ad-account-custodian repository directory
4. **Branch**: The `prod` branch must exist on the remote repository
5. **Configuration**: AD-Account-Custodian.yaml must be properly configured with MaxUsersPerRun setting

## Configuration Notes

The `MaxUsersPerRun` setting in the YAML configuration limits the number of users processed per execution:
- Default: 100 users per run
- Set to 0 or remove to process all users
- Helps prevent overwhelming AD or running too long in large environments

## Troubleshooting

**"Git operations failed"**: Check network connectivity and ensure `prod` branch exists on remote
**"PowerShell execution errors"**: Ensure PowerShell execution policy allows script execution
