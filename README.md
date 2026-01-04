# Refactored Adventure: Sovereign Windows Optimizer

A configuration-driven PowerShell engine for Windows 10/11 Hardening and Optimization.

## Features
- **Idempotent:** Safe to run multiple times.
- **Config-First:** Edit `sovereign-config.json` to change behavior, not the code.
- **Hardware Aware:** Detects Laptops (Battery) and SSDs to prevent bad optimizations.
- **Safe Fail:** Creates .reg backups of every specific key change.

## Usage

1. Clone the repository.
2. Run the script once to generate the config file:
   ```powershell
   .\Optimize-Sovereign.ps1
