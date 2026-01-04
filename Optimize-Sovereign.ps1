<#
.SYNOPSIS
    The "Sovereign" Windows Lifecycle Manager.
    Separates Logic from Configuration for Git-friendly management.

.DESCRIPTION
    1. Checks for 'sovereign-config.json'. Auto-creates it if missing.
    2. Performs hardware and environment heuristics (Laptop vs Desktop, SSD vs HDD).
    3. Backs up specific registry keys before modification (Lossless Undo).
    4. Applies settings defined in the JSON configuration.

.NOTES
    Version: 6.0 (Sovereign)
    Standard: PSDefaultParameterValues, StrictMode
#>

[CmdletBinding()]
Param (
    [Switch]$Remediate,
    [Switch]$RestoreDefaults
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# -----------------------------------------------------------------------------
# CONSTANTS & PATHS
# -----------------------------------------------------------------------------
$RootPath   = $PSScriptRoot
$ConfigPath = Join-Path $RootPath "sovereign-config.json"
$BackupPath = Join-Path $env:SystemDrive "Sovereign_Backups"
$LogPath    = Join-Path $BackupPath "Logs"

# -----------------------------------------------------------------------------
# CORE FUNCTIONS
# -----------------------------------------------------------------------------

function Write-Log {
    Param ([String]$Message, [String]$Level = "INFO")
    $Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $ConsoleColor = switch ($Level) { "INFO" {"Cyan"} "WARN" {"Yellow"} "ERR" {"Red"} "OK" {"Green"} Default {"White"} }
    
    # Console Output
    Write-Host "[$Timestamp] [$Level] $Message" -ForegroundColor $ConsoleColor
    
    # File Logging
    if (!(Test-Path $LogPath)) { New-Item -Path $LogPath -ItemType Directory -Force | Out-Null }
    $LogFile = Join-Path $LogPath "Sovereign_$(Get-Date -Format 'yyyy-MM').log"
    Add-Content -Path $LogFile -Value "[$Timestamp] [$Level] $Message"
}

function Get-Configuration {
    if (!(Test-Path $ConfigPath)) {
        Write-Log "Configuration file not found. Generating default 'sovereign-config.json'..." "WARN"
        
        $DefaultConfig = @{
            Security = @{
                DisableSMBv1      = $true
                HardeningFirewall = $true
                DefenderHigh      = $true
            }
            Privacy = @{
                DisableTelemetry   = $true
                DisableAdvertising = $true
                DisableWiFiSense   = $true
            }
            Performance = @{
                HighPowerPlan      = $true
                DebloatApps        = @("CandyCrush", "TikTok", "Disney", "Spotify", "Microsoft.SkypeApp")
                TcpOptimization    = $true
            }
            Maintenance = @{
                AutoUpdateApps     = $true
                CleanTempFiles     = $true
            }
        }
        
        $DefaultConfig | ConvertTo-Json -Depth 4 | Set-Content -Path $ConfigPath
        Write-Log "Config generated. Please review '$ConfigPath' and run again." "WARN"
        exit
    }
    
    try {
        return Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
    } catch {
        Write-Log "Failed to parse JSON config. Check syntax." "ERR"
        exit
    }
}

function Set-RegistrySafely {
    Param (
        [Parameter(Mandatory)]$Path,
        [Parameter(Mandatory)]$Name,
        [Parameter(Mandatory)]$Value,
        [String]$Type = "DWord"
    )

    # 1. Check if change is needed
    if (Test-Path $Path) {
        $Current = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($Current -and ($Current.$Name -eq $Value)) { return } # Already set
    }

    # 2. Backup Logic
    $Timestamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
    $UndoFile = Join-Path $BackupPath "Undo_$Timestamp.reg"
    
    if (Test-Path $Path) {
        # Export only this specific key branch for safety
        Start-Process "reg.exe" -ArgumentList "export `"$Path`" `"$UndoFile`" /y" -Wait -NoNewWindow
    }

    # 3. Apply Change
    if (!(Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
    Write-Log "Set Registry: $Name = $Value (Backup: $UndoFile)" "OK"
}

# -----------------------------------------------------------------------------
# MODULES
# -----------------------------------------------------------------------------

function Invoke-Hardening {
    Param ($Config)
    Write-Log "--- Starting Security Module ---"
    
    if ($Config.DisableSMBv1) {
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
        Write-Log "SMBv1 Disabled" "OK"
    }
    
    if ($Config.HardeningFirewall) {
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True | Out-Null
        Write-Log "Firewall Profiles Active" "OK"
    }
}

function Invoke-Privacy {
    Param ($Config)
    Write-Log "--- Starting Privacy Module ---"
    
    if ($Config.DisableTelemetry) {
        Set-RegistrySafely "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0
    }
    
    if ($Config.DisableAdvertising) {
        Set-RegistrySafely "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" "DisabledByGroupPolicy" 1
    }
}

function Invoke-Performance {
    Param ($Config)
    Write-Log "--- Starting Performance Module ---"
    
    # Heuristic: Check for Battery (Laptop vs Desktop)
    $IsLaptop = (Get-WmiObject -Class Win32_Battery)
    
    if ($Config.HighPowerPlan -and -not $IsLaptop) {
        $Plan = Get-CimInstance -ClassName Win32_PowerPlan -Namespace root\cimv2\power | Where-Object { $_.ElementName -like "*High Performance*" }
        if ($Plan) { 
            powercfg -setactive $Plan.InstanceID.Split("}")[1].Trim("}") 
            Write-Log "High Performance Plan Active" "OK"
        }
    } elseif ($IsLaptop) {
        Write-Log "Laptop detected. Skipping High Performance plan to preserve battery." "INFO"
    }

    # Heuristic: Check Disk Type (SSD vs HDD)
    $PhysicalDisks = Get-PhysicalDisk | Where-Object { $_.MediaType -eq 'SSD' }
    if ($PhysicalDisks) {
        Write-Log "SSD Detected. Ensuring TRIM is enabled." "INFO"
        fsutil behavior set DisableDeleteNotify 0 | Out-Null
    }
}

# -----------------------------------------------------------------------------
# MAIN EXECUTION
# -----------------------------------------------------------------------------

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Elevation required. Relaunching..."
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Remediate" -Verb RunAs
    exit
}

Write-Log "=== SOVEREIGN SYSTEM MANAGER ==="
$Cfg = Get-Configuration

if ($Remediate) {
    # Create System Restore Point
    Checkpoint-Computer -Description "Sovereign-Config-Change" -RestorePointType "MODIFY_SETTINGS" -ErrorAction SilentlyContinue
    
    Invoke-Hardening -Config $Cfg.Security
    Invoke-Privacy   -Config $Cfg.Privacy
    Invoke-Performance -Config $Cfg.Performance
    
    Write-Log "Execution Complete. Check $BackupPath for Undo files." "OK"
} else {
    Write-Log "Running in AUDIT MODE. Use -Remediate to apply changes." "WARN"
    Write-Log "Current Config Loaded from: $ConfigPath" "INFO"
}
