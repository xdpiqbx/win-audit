# Windows_Vuln_Check.ps1
# Read-only Windows security audit
# Windows PowerShell 5.1+
# No configuration changes, no installations.

$ErrorActionPreference = "Continue"

$BaseDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$ReportFile = Join-Path $BaseDir "Windows_Vuln_Report.txt"
$Report = New-Object System.Collections.Generic.List[string]

$script:CurrentSection = "Header"
$script:AuditFindings = New-Object System.Collections.Generic.List[string]

function Add-Line {
    param([string]$Text)

    [void]$Report.Add($Text)
    Write-Host $Text

    if ($Text -match '\[(WARNING|UNKNOWN|REVIEW)\]') {
        [void]$script:AuditFindings.Add(($script:CurrentSection + " :: " + $Text.Trim()))
    }
}

function Invoke-Check {
    param(
        [string]$Name,
        [scriptblock]$Action
    )

    Add-Line ""
    Add-Line "============================================================"
    $script:CurrentSection = $Name
    Add-Line $Name
    Add-Line "============================================================"

    try {
        $Result = @(& $Action 2>&1)

        if ($Result.Count -eq 0) {
            Add-Line "[UNKNOWN] No data returned."
        }
        else {
            foreach ($Item in $Result) {
                if ($null -ne $Item) {
                    Add-Line ([string]$Item)
                }
            }
        }
    }
    catch {
        Add-Line ("[UNKNOWN] " + $_.Exception.Message)
    }
}

function Get-RegValue {
    param(
        [string]$Path,
        [string]$Name
    )

    try {
        $Item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        return $Item.$Name
    }
    catch {
        return $null
    }
}

function Protect-Text {
    param([string]$Text)

    return ($Text -replace '(?i)(password|passwd|pwd|token|secret|api[_-]?key)(\s*[=:]\s*|\s+)("[^"]*"|\S+)', '$1$2[REDACTED]')
}

Add-Line "WINDOWS SECURITY AUDIT"
Add-Line ("Date: " + (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
Add-Line ("Computer: " + $env:COMPUTERNAME)
Add-Line ("User: " + $env:USERNAME)
Add-Line ("PowerShell: " + $PSVersionTable.PSVersion)

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Add-Line ("Elevated (Administrator): " + $IsAdmin)
if (-not $IsAdmin) {
    Add-Line "[WARNING] Not elevated. BitLocker, Secure Boot, SMB server, optional features and some process details will show UNKNOWN."
    Add-Line "[WARNING] Re-run from PowerShell started with 'Run as administrator' for a complete audit."
}
Add-Line "[INFO] This report contains user names, SIDs, software and process paths. Do not share it publicly."
$SummaryInsertIndex = $Report.Count

# ============================================================
# 000 Last network connectivity
# ============================================================

Invoke-Check "000. Last network connectivity" {

    $Events = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-NetworkProfile/Operational'
        Id = 10000
    } -MaxEvents 100 -ErrorAction Stop

    if ($Events) {
        $LastEvent = $Events |
            Sort-Object TimeCreated -Descending |
            Select-Object -First 1

        "Last network connection: $($LastEvent.TimeCreated)"
        "Details: $(($LastEvent.Message -split "`n" | Select-Object -First 3) -join ' | ')"
    }
    else {
        "[UNKNOWN] No network connection events found."
    }
}

# ============================================================
# 01. WINDOWS VERSION AND UPDATES
# ============================================================

Invoke-Check "01. Windows version and recent updates" {

    $OS = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop

    "OS: $($OS.Caption)"
    "Version: $($OS.Version)"
    "Build: $($OS.BuildNumber)"
    "Install date: $($OS.InstallDate)"

    "Recent installed updates:"

    $Hotfixes = Get-HotFix -ErrorAction SilentlyContinue |
        Sort-Object InstalledOn -Descending |
        Select-Object -First 5

    if ($Hotfixes) {
        foreach ($Hotfix in $Hotfixes) {
            "$($Hotfix.HotFixID) | $($Hotfix.InstalledOn)"
        }
    }
    else {
        "[UNKNOWN] Update history unavailable."
    }

    "[INFO] Recent KB entries do not prove that every security update is installed."
}

# ============================================================
# 02. ANTIVIRUS PRODUCTS
# ============================================================

Invoke-Check "02. Installed antivirus products" {

    $AV = Get-CimInstance `
        -Namespace root/SecurityCenter2 `
        -ClassName AntivirusProduct `
        -ErrorAction Stop

    if ($AV) {
        foreach ($Product in $AV) {
            "Antivirus: $($Product.displayName)"
        }
    }
    else {
        "[WARNING] Windows Security Center reports no antivirus product."
    }
}

# ============================================================
# 03. MICROSOFT DEFENDER
# ============================================================

Invoke-Check "03. Microsoft Defender status" {

    if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
        throw "Get-MpComputerStatus unavailable."
    }

    $D = Get-MpComputerStatus -ErrorAction Stop

    $Mode = ""
    if ($D.PSObject.Properties.Name -contains "AMRunningMode") {
        $Mode = [string]$D.AMRunningMode
    }

    $Passive = ($Mode -ne "" -and $Mode -ne "Normal")
    $Bad = if ($Passive) { "[INFO]" } else { "[WARNING]" }

    "Running mode: $(if ($Mode) { $Mode } else { 'n/a' })"
    "Antivirus enabled: $($D.AntivirusEnabled)"
    "Real-time protection: $($D.RealTimeProtectionEnabled)"
    "Behavior monitoring: $($D.BehaviorMonitorEnabled)"
    "Downloaded file scanning: $($D.IoavProtectionEnabled)"
    "Tamper protection: $($D.IsTamperProtected)"
    "Signatures last updated: $($D.AntivirusSignatureLastUpdated)"
    "Signature age (days): $($D.AntivirusSignatureAge)"
    "Quick scan age (days): $($D.QuickScanAge)"
    "Full scan age (days): $($D.FullScanAge)"
    ""

    if ($Passive) {
        "[INFO] Defender runs in '$Mode' mode (another antivirus is probably primary). Defender results below are informational only."
    }

    if ($D.AntivirusEnabled) { "[OK] Antivirus engine is enabled." } else { "$Bad Antivirus engine is disabled." }
    if ($D.RealTimeProtectionEnabled) { "[OK] Real-time protection is on." } else { "$Bad Real-time protection is off." }
    if ($D.BehaviorMonitorEnabled) { "[OK] Behavior monitoring is on." } else { "$Bad Behavior monitoring is off." }
    if ($D.IoavProtectionEnabled) { "[OK] Downloaded file scanning is on." } else { "$Bad Downloaded file scanning is off." }
    if ($D.IsTamperProtected) { "[OK] Tamper protection is on." } else { "$Bad Tamper protection is off or unknown." }

    if ($null -ne $D.AntivirusSignatureAge) {
        if ([int64]$D.AntivirusSignatureAge -gt 7) {
            "$Bad Signatures are older than 7 days."
        }
        else {
            "[OK] Signatures are up to date."
        }
    }

    if ($null -ne $D.QuickScanAge) {
        $Quick = [int64]$D.QuickScanAge

        if ($Quick -ge 4294967295) {
            "[INFO] No quick scan has been recorded."
        }
        elseif ($Quick -gt 14) {
            "$Bad Last quick scan was more than 14 days ago."
        }
        else {
            "[OK] Quick scan is recent."
        }
    }

    "[INFO] If another antivirus is active, Defender may operate in passive mode."
}

# ============================================================
# 03a. DEFENDER EXCLUSIONS
# ============================================================

Invoke-Check "03a. Microsoft Defender exclusions" {

    if (-not (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)) {
        throw "Get-MpPreference unavailable."
    }

    if (-not $IsAdmin) {
        throw "Administrator rights are required to read Defender exclusions."
    }

    $P = Get-MpPreference -ErrorAction Stop

    $ExPaths = @($P.ExclusionPath | Where-Object { $_ })
    $ExExts = @($P.ExclusionExtension | Where-Object { $_ })
    $ExProcs = @($P.ExclusionProcess | Where-Object { $_ })
    $ExTotal = $ExPaths.Count + $ExExts.Count + $ExProcs.Count

    "Path exclusions: $($ExPaths.Count)"
    foreach ($X in $ExPaths) {
        "  Path: $X"

        if ($X -match '(?i)^[a-z]:\\?\*?$|\\Users\\?\*?$|\\Temp\\?|\\Downloads\\?|\\AppData\\?|\\Windows\\?\*?$') {
            "[REVIEW] Broad or high-risk path exclusion: $X"
        }
    }

    "Extension exclusions: $($ExExts.Count)"
    foreach ($X in $ExExts) {
        "  Extension: $X"

        if (([string]$X).TrimStart('.') -match '(?i)^(exe|dll|ps1|bat|cmd|vbs|js|scr|msi|com)$') {
            "[REVIEW] Executable or script extension excluded: $X"
        }
    }

    "Process exclusions: $($ExProcs.Count)"
    foreach ($X in $ExProcs) {
        "  Process: $X"
    }

    ""

    if ($ExTotal -eq 0) {
        "[OK] No Defender exclusions are configured."
    }
    else {
        "[WARNING] $ExTotal Defender exclusion(s) configured. Make sure each one was added on purpose."
        "[INFO] Developer folders and games are common legitimate exclusions; malware also adds its own."
    }
}

# ============================================================
# 03b. DEFENDER DETECTION HISTORY
# ============================================================

Invoke-Check "03b. Microsoft Defender detection history" {

    if (-not (Get-Command Get-MpThreatDetection -ErrorAction SilentlyContinue)) {
        throw "Get-MpThreatDetection unavailable."
    }

    $Detections = @(
        Get-MpThreatDetection -ErrorAction Stop |
            Sort-Object InitialDetectionTime -Descending
    )

    if ($Detections.Count -eq 0) {
        "[INFO] No detections in Defender history."
        "[INFO] This also appears if another antivirus is primary or the history was cleared."
        return
    }

    $ThreatNames = @{}

    try {
        foreach ($T in @(Get-MpThreat -ErrorAction Stop)) {
            $ThreatNames[[string]$T.ThreatID] = $T.ThreatName
        }
    }
    catch {}

    "Detections in history: $($Detections.Count) (showing newest 10)"

    foreach ($Det in ($Detections | Select-Object -First 10)) {

        $ThreatKey = [string]$Det.ThreatID
        $ThreatLabel = if ($ThreatNames.ContainsKey($ThreatKey)) { $ThreatNames[$ThreatKey] } else { "ThreatID $ThreatKey" }

        ""
        "Time: $($Det.InitialDetectionTime)"
        "Threat: $ThreatLabel"
        "Process: $($Det.ProcessName)"
        "Resources: $((@($Det.Resources) | Select-Object -First 3) -join '; ')"
        "Action succeeded: $($Det.ActionSuccess)"
        "User: $($Det.DomainUser)"

        if ($Det.ActionSuccess -eq $false) {
            "[WARNING] Defender could not fully remediate this threat."
        }
    }

    $Cutoff = (Get-Date).AddDays(-30)
    $RecentCount = @($Detections | Where-Object { $_.InitialDetectionTime -gt $Cutoff }).Count

    ""

    if ($RecentCount -gt 0) {
        "[WARNING] $RecentCount detection(s) in the last 30 days."
    }
    else {
        "[INFO] No detections in the last 30 days."
    }
}

# ============================================================
# 04. WINDOWS FIREWALL
# ============================================================

Invoke-Check "04. Windows Firewall" {

    if (-not (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
        throw "Get-NetFirewallProfile unavailable."
    }

    $Profiles = Get-NetFirewallProfile -ErrorAction Stop

    foreach ($Profile in $Profiles) {

        if ($Profile.Enabled) {
            "[OK] $($Profile.Name): Firewall enabled"
        }
        else {
            "[WARNING] $($Profile.Name): Firewall disabled"
        }
    }
}

# ============================================================
# 05. SMBv1
# ============================================================

Invoke-Check "05. SMBv1 protocol security" {

    try {
        $SMB = Get-SmbServerConfiguration -ErrorAction Stop

        if ($SMB.EnableSMB1Protocol -eq $false) {
            "[OK] SMBv1 is disabled."
        }
        elseif ($SMB.EnableSMB1Protocol -eq $true) {
            "[WARNING] SMBv1 is enabled. This computer can accept SMBv1 connections."
        }
        else {
            "[UNKNOWN] SMBv1 server state could not be established."
        }
    }
    catch {
        "[UNKNOWN] Could not query SMBv1 server configuration."
    }
}

# ============================================================
# 06. REMOTE DESKTOP
# ============================================================

Invoke-Check "06. Remote Desktop (RDP)" {

    $Value = Get-RegValue `
        "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" `
        "fDenyTSConnections"

    "fDenyTSConnections: $Value"

    if ($Value -eq 1) {
        "[OK] RDP is disabled."
    }
    elseif ($Value -eq 0) {
        "[WARNING] RDP is enabled."
    }
    else {
        "[UNKNOWN] RDP state unavailable."
    }
}

# ============================================================
# 07. LOCAL USERS
# ============================================================

Invoke-Check "07. Local user accounts" {

    if (-not (Get-Command Get-LocalUser -ErrorAction SilentlyContinue)) {
        throw "Get-LocalUser unavailable."
    }

    $Users = Get-LocalUser -ErrorAction Stop

    foreach ($User in $Users) {

        ""

        "Name: $($User.Name)"
        "Enabled: $($User.Enabled)"
        "Password required: $($User.PasswordRequired)"
        "Last logon: $($User.LastLogon)"
        "SID: $($User.SID)"

        if ($User.Enabled) {
            "[INFO] Account is enabled."
        }
        else {
            "[INFO] Account is disabled."
        }
    }

    ""
    "[INFO] PasswordRequired=False does NOT prove that the account has an empty password."
}

# ============================================================
# 08. UAC
# ============================================================

Invoke-Check "08. User Account Control (UAC)" {

    try {
        $Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        $UAC = Get-ItemProperty -Path $Path -ErrorAction Stop

        $EnableLUA = $UAC.EnableLUA
        $Prompt = $UAC.ConsentPromptBehaviorAdmin
        $SecureDesktop = $UAC.PromptOnSecureDesktop

        "EnableLUA: $EnableLUA"
        "ConsentPromptBehaviorAdmin: $Prompt"
        "PromptOnSecureDesktop: $SecureDesktop"
        ""

        if ($EnableLUA -ne 1) {
            "[WARNING] UAC is disabled."
        }
        else {
            "[OK] UAC is enabled."

            switch ($Prompt) {
                0 { "[WARNING] No elevation prompt. Administrators elevate silently." }
                1 { "[INFO] Admin approval required; credentials requested on secure desktop." }
                2 { "[INFO] Admin approval required; prompt displayed on secure desktop." }
                3 { "[INFO] Admin approval required (credentials); secure desktop depends on PromptOnSecureDesktop." }
                4 { "[INFO] Admin approval required (consent); secure desktop depends on PromptOnSecureDesktop." }
                5 { "[OK] Standard UAC behavior: consent required for non-Windows binaries." }
                default { "[UNKNOWN] Unrecognized UAC prompt configuration." }
            }

            if ($Prompt -eq 0) {
                "[WARNING] Automatic elevation reduces protection against unauthorized changes."
            }

            if ($SecureDesktop -eq 1) {
                "[OK] UAC prompts use the secure desktop."
            }
            elseif ($SecureDesktop -eq 0) {
                "[WARNING] UAC prompts do not use the secure desktop."
            }
            else {
                "[UNKNOWN] Secure desktop setting is not recognized."
            }
        }
    }
    catch {
        "[UNKNOWN] Could not read UAC configuration."
    }
}

# ============================================================
# 09. SECURE BOOT
# ============================================================

Invoke-Check "09. Secure Boot" {

    if (-not (Get-Command Confirm-SecureBootUEFI -ErrorAction SilentlyContinue)) {
        throw "Confirm-SecureBootUEFI unavailable."
    }

    try {
        $SecureBoot = Confirm-SecureBootUEFI -ErrorAction Stop

        "Secure Boot: $SecureBoot"

        if ($SecureBoot) {
            "[OK] Secure Boot is enabled."
        }
        else {
            "[WARNING] Secure Boot is disabled."
        }
    }
    catch {
        "[UNKNOWN] Secure Boot could not be queried."
        "[INFO] Possible causes: legacy BIOS, unsupported firmware or insufficient permissions."
    }
}

# ============================================================
# 10. PASSWORD POLICY
# ============================================================

Invoke-Check "10. Local password and account lockout policy" {

    $Output = & net.exe accounts 2>&1

    foreach ($Line in $Output) {
        "$Line"
    }

    "[INFO] Pay particular attention to minimum password length,"
    "password history and account lockout threshold."
}

# ============================================================
# 11. POWERSHELL 2.0
# ============================================================

Invoke-Check "11. Legacy PowerShell 2.0" {

    if (-not (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue)) {
        throw "Get-WindowsOptionalFeature unavailable."
    }

    $Feature = Get-WindowsOptionalFeature `
        -Online `
        -FeatureName MicrosoftWindowsPowerShellV2Root `
        -ErrorAction SilentlyContinue

    if (-not $Feature) {
        "[INFO] PowerShell 2.0 feature not found or elevation required."
        "[INFO] Recent Windows 11 builds removed PowerShell 2.0 entirely, which is the safe outcome."
        return
    }

    "PowerShell 2.0 feature state: $($Feature.State)"

    if ($Feature.State -eq "Enabled") {
        "[WARNING] Legacy PowerShell 2.0 is enabled."
        "[INFO] PowerShell 2.0 lacks modern security features and should normally be disabled."
    }
    elseif ($Feature.State -like "Disabled*") {
        "[OK] PowerShell 2.0 is disabled."
    }
    else {
        "[UNKNOWN] Feature state requires review."
    }
}

# ============================================================
# 12. SMB GUEST AUTHENTICATION
# ============================================================

Invoke-Check "12. Insecure SMB guest authentication" {

    try {
        $SMB = Get-SmbClientConfiguration -ErrorAction Stop

        if ($SMB.EnableInsecureGuestLogons -eq $true) {
            "EnableInsecureGuestLogons: True"
            "[WARNING] Insecure guest authentication is ENABLED."
        }
        elseif ($SMB.EnableInsecureGuestLogons -eq $false) {
            "EnableInsecureGuestLogons: False"
            "[OK] Insecure guest authentication is DISABLED."
        }
        else {
            "EnableInsecureGuestLogons: Unknown"
            "[UNKNOWN] Could not determine guest authentication status."
        }
    }
    catch {
        "[UNKNOWN] Could not query SMB client configuration."
    }
}

# ============================================================
# 13. LOCAL ADMINISTRATORS
# ============================================================

Invoke-Check "13. Local Administrators group" {

    if (-not (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue)) {
        throw "Get-LocalGroupMember unavailable."
    }

    $Members = Get-LocalGroupMember -SID "S-1-5-32-544" -ErrorAction Stop

    foreach ($Member in $Members) {
        "Account: $($Member.Name)"
        "Type: $($Member.ObjectClass)"
        "Source: $($Member.PrincipalSource)"
        ""
    }

    "[INFO] Every unexpected administrator account should be reviewed."
}

# ============================================================
# 14. BITLOCKER
# ============================================================

Invoke-Check "14. BitLocker system drive encryption" {

    if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
        throw "Get-BitLockerVolume unavailable (BitLocker cmdlets are missing on Windows Home; Device Encryption may be used instead)."
    }

    $Volume = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop

    "Mount point: $($Volume.MountPoint)"
    "Protection status: $($Volume.ProtectionStatus)"
    "Volume status: $($Volume.VolumeStatus)"
    "Encryption percentage: $($Volume.EncryptionPercentage)"

    if ($Volume.ProtectionStatus -eq "On") {
        "[OK] BitLocker protection is active."
    }
    elseif ($Volume.ProtectionStatus -eq "Off") {
        "[WARNING] BitLocker protection is not active."
    }
    else {
        "[INFO] BitLocker state requires review."
    }
}

# ============================================================
# 15. LSASS PROTECTION
# ============================================================

Invoke-Check "15. LSASS protection" {

    try {
        $Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        $Config = Get-ItemProperty -Path $Path -ErrorAction Stop

        $Value = $Config.RunAsPPL

        "RunAsPPL: $(if ($null -eq $Value) {'Not configured'} else {$Value})"

        if ($Value -eq 1) {
            "[OK] LSASS protection enabled (with UEFI lock)."
        }
        elseif ($Value -eq 2) {
            "[OK] LSASS protection enabled (without UEFI lock)."
        }
        elseif ($Value -eq 0) {
            "[WARNING] LSASS protection explicitly disabled."
        }
        else {
            "[UNKNOWN] RunAsPPL is not set in the registry."
            "[INFO] Recent Windows 11 may enable LSA protection by default. Verify in Windows Security > Device security > Core isolation details."
        }
    }
    catch {
        "[UNKNOWN] Could not read LSASS protection settings."
    }
}

# ============================================================
# 16. UNQUOTED SERVICE PATHS
# ============================================================

Invoke-Check "16. Unquoted service executable paths" {

    $Services = Get-CimInstance Win32_Service -ErrorAction Stop
    $Count = 0

    foreach ($Service in $Services) {

        $RawPath = [string]$Service.PathName

        if ([string]::IsNullOrWhiteSpace($RawPath)) {
            continue
        }

        $Trimmed = $RawPath.TrimStart()

        if ($Trimmed.StartsWith('"')) {
            continue
        }

        if ($Trimmed -match '^(.+?\.exe)(?:\s|$)') {

            $ExePath = $Matches[1].Trim()

            if ($ExePath -match '\s') {

                $Count++

                "[WARNING] Potential unquoted service path"
                "Service: $($Service.Name)"
                "Display name: $($Service.DisplayName)"
                "Executable path: $ExePath"
                "Full command: $RawPath"
                ""
            }
        }
    }

    if ($Count -eq 0) {
        "[OK] No potential unquoted service paths found."
    }
    else {
        "[WARNING] $Count potential cases found."
        "[INFO] Exploitability depends on writable candidate paths and ACL permissions."
    }
}

# ============================================================
# 17. UNSIGNED DEVICE DRIVERS
# ============================================================

Invoke-Check "17. Unsigned device drivers" {

    $Drivers = Get-CimInstance Win32_PnPSignedDriver -ErrorAction Stop |
        Where-Object { $_.IsSigned -eq $false }

    if ($Drivers) {

        foreach ($Driver in ($Drivers | Select-Object -First 30)) {

            "Device: $($Driver.DeviceName)"
            "Provider: $($Driver.DriverProviderName)"
            "Version: $($Driver.DriverVersion)"
            "INF: $($Driver.InfName)"
            ""
        }

        "[WARNING] Unsigned drivers require verification."
    }
    else {
        "[OK] No unsigned drivers reported by this query."
    }
}

# ============================================================
# 18. WINRM
# ============================================================

Invoke-Check "18. Windows Remote Management (WinRM)" {

    $Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"

    $Unencrypted = Get-RegValue $Path "AllowUnencryptedTraffic"
    $Basic = Get-RegValue $Path "AllowBasic"

    "AllowUnencryptedTraffic: $Unencrypted"
    "AllowBasic: $Basic"

    $Service = Get-Service -Name WinRM -ErrorAction Stop

    "Service status: $($Service.Status)"
    "Startup type: $($Service.StartType)"

    if ($Service.Status -eq "Running") {
        "[INFO] WinRM is running and provides remote management capability."
    }

    if ($Unencrypted -eq 1) {
        "[WARNING] Unencrypted WinRM traffic is allowed by policy."
    }

    if ($Basic -eq 1) {
        "[WARNING] Basic authentication is allowed by policy."
    }

    if ($Service.Status -ne "Running") {
        "[OK] WinRM service is not currently running."
    }
}



# ============================================================
# 19. LISTENING TCP PORTS - SECURITY AUDIT
# ============================================================

$Section19Lines = New-Object 'System.Collections.Generic.List[string]'

function Add-Section19Line {
    param([string]$Text = "")
    [void]$Section19Lines.Add($Text)
}

function Get-PortPurpose {
    param([int]$Port)

    switch ($Port) {
        21    { "FTP"; break }
        22    { "SSH"; break }
        23    { "Telnet"; break }
        25    { "SMTP"; break }
        53    { "DNS"; break }
        80    { "HTTP"; break }
        135   { "RPC Endpoint Mapper"; break }
        139   { "NetBIOS Session Service"; break }
        443   { "HTTPS"; break }
        445   { "SMB"; break }
        902   { "VMware Authentication"; break }
        912   { "VMware Authentication"; break }
        1433  { "Microsoft SQL Server"; break }
        2179  { "Hyper-V VM Connection"; break }
        3389  { "Remote Desktop (RDP)"; break }
        5357  { "Web Services for Devices (WSD)"; break }
        5985  { "WinRM HTTP"; break }
        5986  { "WinRM HTTPS"; break }
        7680  { "Windows Delivery Optimization"; break }
        5040  { "Connected Devices Platform"; break }
        default {
            if ($Port -ge 49152 -and $Port -le 65535) {
                "Dynamic/private TCP port range"
            }
            else {
                "Unknown / Application-specific"
            }
        }
    }
}

Add-Section19Line ""
Add-Section19Line "============================================================"
Add-Section19Line "19. Listening TCP ports - security audit"
Add-Section19Line "============================================================"

# Firewall status only
Add-Section19Line ""
Add-Section19Line "[Firewall]"

try {
    $FirewallProfiles = @(Get-NetFirewallProfile -ErrorAction Stop)

    foreach ($Profile in $FirewallProfiles) {
        if ($Profile.Enabled) {
            Add-Section19Line "[OK] $($Profile.Name): Enabled"
        }
        else {
            Add-Section19Line "[WARNING] $($Profile.Name): Disabled"
        }
    }
}
catch {
    Add-Section19Line "[UNKNOWN] Cannot retrieve Firewall status"
}

# TCP listeners
Add-Section19Line ""
Add-Section19Line "[TCP LISTENERS]"

try {
    $Listeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop)
}
catch {
    $Listeners = @()
    Add-Section19Line "[ERROR] Cannot retrieve TCP listeners: $($_.Exception.Message)"
}

if ($Listeners.Count -eq 0) {
    Add-Section19Line "[INFO] No TCP listeners found or access unavailable."
}
else {

    # Retrieve service information
    $ServiceMap = @{}

    try {
        $AllServices = @(Get-CimInstance Win32_Service -ErrorAction Stop)

        foreach ($Service in $AllServices) {
            if ($Service.ProcessId -gt 0) {
                $ServicePid = [int]$Service.ProcessId

                if (-not $ServiceMap.ContainsKey($ServicePid)) {
                    $ServiceMap[$ServicePid] = @()
                }

                $ServiceMap[$ServicePid] += $Service.Name
            }
        }
    }
    catch {
        Add-Section19Line "[WARNING] Windows service information unavailable."
    }

    $ProcessGroups = @(
        $Listeners |
        Group-Object OwningProcess |
        Sort-Object { [int]$_.Name }
    )

    foreach ($ProcessGroup in $ProcessGroups) {

        $ProcessId = [int]$ProcessGroup.Name

        $ProcessName = "UNKNOWN"
        $ProcessPath = "UNKNOWN"
        $CommandLine = "UNKNOWN"

        if ($ProcessId -eq 4) {
            $ProcessName = "System"
            $ProcessPath = "Windows kernel"
            $CommandLine = "N/A"
        }
        else {
            # Individual CIM query for each PID
            try {
                $CimProcess = Get-CimInstance `
                    -ClassName Win32_Process `
                    -Filter "ProcessId = $ProcessId" `
                    -ErrorAction Stop

                if ($CimProcess) {
                    if ($CimProcess.Name) {
                        $ProcessName = $CimProcess.Name
                    }

                    if ($CimProcess.ExecutablePath) {
                        $ProcessPath = $CimProcess.ExecutablePath
                    }

                    if ($CimProcess.CommandLine) {
                        $CommandLine = $CimProcess.CommandLine
                    }
                }
            }
            catch {}

            # Fallback: Get-Process
            if ($ProcessPath -eq "UNKNOWN" -or
                $ProcessName -eq "UNKNOWN") {

                try {
                    $ProcessObject = Get-Process `
                        -Id $ProcessId `
                        -ErrorAction Stop

                    if ($ProcessName -eq "UNKNOWN") {
                        $ProcessName = $ProcessObject.ProcessName + ".exe"
                    }

                    if ($ProcessPath -eq "UNKNOWN" -and $ProcessObject.Path) {
                        $ProcessPath = $ProcessObject.Path
                    }
                }
                catch {}
            }
        }

        # Redact credentials in command line
        if ($CommandLine -ne "UNKNOWN" -and
            $CommandLine -ne "N/A") {

            $CommandLine = $CommandLine -replace `
                '(?i)(password|passwd|pwd|token|secret|api[_-]?key)(\s*[=:]\s*|\s+)(\"[^\"]*\"|\S+)', `
                '$1$2[REDACTED]'
        }

        $Services = "None"

        if ($ServiceMap.ContainsKey($ProcessId)) {
            $Services = (
                $ServiceMap[$ProcessId] |
                Sort-Object -Unique
            ) -join ", "
        }

        Add-Section19Line ""
        Add-Section19Line "------------------------------------------------------------"
        Add-Section19Line "PID:          $ProcessId"
        Add-Section19Line "PROCESS:      $ProcessName"
        Add-Section19Line "PATH:         $ProcessPath"
        Add-Section19Line "SERVICES:     $Services"
        Add-Section19Line "COMMAND LINE: $CommandLine"

        $PortGroups = @(
            $ProcessGroup.Group |
            Group-Object LocalPort |
            Sort-Object { [int]$_.Name }
        )

        foreach ($PortGroup in $PortGroups) {

            $Port = [int]$PortGroup.Name

            $Addresses = @(
                $PortGroup.Group.LocalAddress |
                Sort-Object -Unique
            )

            $AddressText = $Addresses -join ", "
            $Purpose = Get-PortPurpose -Port $Port

            Add-Section19Line ""
            Add-Section19Line "  TCP PORT:   $Port"
            Add-Section19Line "  ADDRESS:    $AddressText"
            Add-Section19Line "  PURPOSE:    $Purpose"

            if ($Addresses.Count -gt 0 -and
                @($Addresses | Where-Object {
                    $_ -notin @("127.0.0.1", "::1")
                }).Count -eq 0) {

                Add-Section19Line "  EXPOSURE:   Localhost only"
            }
            elseif ($Addresses -contains "0.0.0.0" -or
                    $Addresses -contains "::") {

                Add-Section19Line "  EXPOSURE:   All applicable network interfaces"
            }
            else {
                Add-Section19Line "  EXPOSURE:   Specific network interface"
            }

            if ($Purpose -like "Unknown*") {
                Add-Section19Line "  STATUS:     [REVIEW] Identify the application using this port."
            }
        }
    }

    $UniquePorts = @(
        $Listeners |
        Select-Object -ExpandProperty LocalPort -Unique
    )

    Add-Section19Line ""
    Add-Section19Line "------------------------------------------------------------"
    Add-Section19Line "[SUMMARY]"
    Add-Section19Line "Processes: $($ProcessGroups.Count)"
    Add-Section19Line "Unique TCP ports: $($UniquePorts.Count)"
    Add-Section19Line "Listening TCP sockets: $($Listeners.Count)"
    Add-Section19Line "Firewall rule analysis: Not performed"
    Add-Section19Line ""
    Add-Section19Line "[INFO] 127.0.0.1 and ::1 indicate localhost-only binding."
    Add-Section19Line "[INFO] 0.0.0.0 and :: indicate listening on all applicable interfaces."
    Add-Section19Line "[INFO] Listening does not by itself prove that a port is reachable remotely."
}

Add-Section19Line "============================================================"

# Copy section 19 into the report (console + txt file).
$script:CurrentSection = "19. Listening TCP ports - security audit"
foreach ($Line in $Section19Lines) {
    Add-Line $Line
}


# ============================================================
# 20. THIRD-PARTY SOFTWARE
# ============================================================

Invoke-Check "20. Installed third-party software (Microsoft excluded)" {

    $Paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $Apps = foreach ($Path in $Paths) {

        Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue |
            Where-Object {
                $_.DisplayName -and
                $_.DisplayName -notmatch '(?i)^Microsoft\b' -and
                $_.Publisher -notmatch '(?i)\bMicrosoft\b'
            } |
            Select-Object DisplayName, DisplayVersion, Publisher
    }

    $Apps = @(
        $Apps |
            Sort-Object DisplayName, DisplayVersion -Unique
    )

    "Third-party application entries: $($Apps.Count)"
    ""

    foreach ($App in $Apps) {

        "Name: $($App.DisplayName)"
        "Version: $($App.DisplayVersion)"
        "Publisher: $($App.Publisher)"
        ""
    }

    "[INFO] Microsoft products and Microsoft publishers are excluded."
    "[INFO] Software inventory alone does not establish whether a version is vulnerable."
}

# ============================================================
# 21. ACL - CRITICAL DIRECTORIES
# ============================================================

Invoke-Check "21. ACL permissions on critical system directories" {

    $CriticalDirs = @(
        $env:windir
        "$env:windir\System32"
        "$env:windir\System32\drivers"
        $env:ProgramFiles
        ${env:ProgramFiles(x86)}
        $env:ProgramData
    ) | Where-Object {
        $_ -and (Test-Path -LiteralPath $_ -PathType Container)
    } | Select-Object -Unique

    $BroadSIDs = @(
        "S-1-1-0"       # Everyone
        "S-1-5-11"      # Authenticated Users
        "S-1-5-32-545"  # Users
    )

    # Write, modify, delete and ACL-management rights
    $RiskMask = [uint32](
        0x00000002 -bor  # WriteData / CreateFiles
        0x00000004 -bor  # AppendData / CreateDirectories
        0x00000010 -bor  # WriteExtendedAttributes
        0x00000040 -bor  # DeleteSubdirectoriesAndFiles
        0x00000100 -bor  # WriteAttributes
        0x00010000 -bor  # Delete
        0x00040000 -bor  # ChangePermissions
        0x00080000 -bor  # TakeOwnership
        0x10000000 -bor  # GenericAll
        0x40000000       # GenericWrite
    )

    $Findings = 0
    $Errors = 0

    foreach ($Directory in $CriticalDirs) {

        try {
            $ACL = Get-Acl -LiteralPath $Directory -ErrorAction Stop

            foreach ($ACE in $ACL.Access) {

                if ($ACE.AccessControlType -ne "Allow") {
                    continue
                }

                try {
                    $SID = $ACE.IdentityReference.Translate(
                        [System.Security.Principal.SecurityIdentifier]
                    ).Value
                }
                catch {
                    continue
                }

                if ($SID -notin $BroadSIDs) {
                    continue
                }

                $RightsMask = [BitConverter]::ToUInt32(
                    [BitConverter]::GetBytes(
                        [int]$ACE.FileSystemRights
                    ), 0
                )

                if (($RightsMask -band $RiskMask) -eq 0) {
                    continue
                }

                $Findings++

                "[WARNING] Potentially unsafe permission"
                "Directory: $Directory"
                "Principal: $($ACE.IdentityReference.Value)"
                "Rights: $($ACE.FileSystemRights)"
                "Inherited: $($ACE.IsInherited)"
                ""
            }
        }
        catch {
            $Errors++
            "[UNKNOWN] Cannot read ACL: $Directory"
        }
    }

    if ($Findings -eq 0 -and $Errors -eq 0) {
        "[OK] No broad write permissions detected."
    }
    elseif ($Findings -gt 0) {
        "[WARNING] $Findings potentially unsafe ACL entries found."
    }

    if ($Errors -gt 0) {
        "[UNKNOWN] ACL could not be checked on $Errors director(ies)."
    }

    "[INFO] C:\ProgramData normally gives Users create-files/create-folders rights by default; treat that entry as expected."
    "[INFO] Findings on Windows, System32 or Program Files are the ones that really matter."
}

# ============================================================
# 22. SUSPICIOUS SCHEDULED TASK ACTIONS
# ============================================================

Invoke-Check "22. Scheduled tasks with potentially suspicious actions" {

    if (-not (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        throw "Get-ScheduledTask unavailable."
    }

    $Tasks = Get-ScheduledTask -ErrorAction Stop |
        Where-Object {
            $_.TaskPath -notlike "\Microsoft\*"
        }

    $FindingCount = 0

    foreach ($Task in $Tasks) {

        foreach ($Action in $Task.Actions) {

            $Execute = [string]$Action.Execute
            $Arguments = [string]$Action.Arguments
            $Combined = "$Execute $Arguments"

            $Suspicious = $false

            if ($Combined -match '(?i)\\AppData\\Local\\Temp\\|\\Users\\Public\\|\\Downloads\\') {
                $Suspicious = $true
            }

            if ($Combined -match '(?i)-encodedcommand|-enc\s|FromBase64String') {
                $Suspicious = $true
            }

            if ($Combined -match '(?i)\bmshta\.exe\b|\bwscript\.exe\b|\bcscript\.exe\b|\bregsvr32\.exe\b') {
                $Suspicious = $true
            }

            if ($Suspicious) {

                $FindingCount++

                "[REVIEW] Potentially suspicious scheduled task"
                "Task: $($Task.TaskPath)$($Task.TaskName)"
                "State: $($Task.State)"
                "Executable: $Execute"
                "Arguments: $Arguments"
                ""
            }
        }
    }

    if ($FindingCount -eq 0) {
        "[INFO] No scheduled task actions matched the selected suspicious patterns."
    }
    else {
        "[WARNING] $FindingCount scheduled task actions require manual review."
    }

    "[INFO] Pattern matches are indicators for investigation, not proof of malicious activity."
}

# ============================================================
# 23. CURRENT SECURITY CONTEXT
# ============================================================

Invoke-Check "23. Current user security context" {

    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()

    $Principal = New-Object Security.Principal.WindowsPrincipal($Identity)

    "Current identity: $($Identity.Name)"

    $Elevated = $Principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )

    "Elevated administrator token: $Elevated"

    if ($Elevated) {
        "[INFO] Current PowerShell session has an elevated administrator token."
    }
    else {
        "[INFO] Current PowerShell session is not elevated."
        "[INFO] An account belonging to Administrators may still have a filtered UAC token."
    }
}

# ============================================================
# 24. AUTOMATIC SIGN-IN
# ============================================================

Invoke-Check "24. Windows automatic sign-in (AutoLogon)" {

    $Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

    $Auto = Get-RegValue $Path "AutoAdminLogon"
    $AutoUser = Get-RegValue $Path "DefaultUserName"
    $AutoPass = Get-RegValue $Path "DefaultPassword"

    $HasPass = ($null -ne $AutoPass -and ([string]$AutoPass) -ne "")
    $AutoText = if ($null -eq $Auto) { "Not set" } else { [string]$Auto }
    $UserText = if ($null -eq $AutoUser) { "Not set" } else { [string]$AutoUser }
    $PassText = if ($HasPass) { "PRESENT (value hidden)" } else { "not present" }

    "AutoAdminLogon: $AutoText"
    "DefaultUserName: $UserText"
    "DefaultPassword in registry: $PassText"

    if (([string]$Auto) -eq "1") {
        "[WARNING] Automatic sign-in is enabled for '$UserText'. Anyone with physical access can sign in without a password."

        if ($HasPass) {
            "[WARNING] A plaintext password is stored in the registry (DefaultPassword)."
        }
        else {
            "[INFO] The password may be stored as an LSA secret (netplwiz or Sysinternals Autologon); it is not visible here."
        }
    }
    else {
        "[OK] Automatic sign-in is not enabled."
    }
}

# ============================================================
# 25. NETWORK SHARES
# ============================================================

Invoke-Check "25. Network shares (non-default)" {

    if (-not (Get-Command Get-SmbShare -ErrorAction SilentlyContinue)) {
        throw "Get-SmbShare unavailable."
    }

    $AllShares = @(Get-SmbShare -ErrorAction Stop)
    $Custom = @($AllShares | Where-Object { -not $_.Special })

    "Total shares: $($AllShares.Count) (default administrative shares such as C$, ADMIN$ and IPC$ are not listed)"

    if ($Custom.Count -eq 0) {
        "[OK] No custom network shares."
        return
    }

    foreach ($Share in $Custom) {

        ""
        "Share: $($Share.Name)"
        "Path: $($Share.Path)"
        "Description: $($Share.Description)"

        try {
            $AccessList = @(Get-SmbShareAccess -Name $Share.Name -ErrorAction Stop)

            foreach ($Entry in $AccessList) {
                "  Access: $($Entry.AccountName) | $($Entry.AccessControlType) | $($Entry.AccessRight)"

                if ("$($Entry.AccessControlType)" -eq "Allow" -and
                    "$($Entry.AccountName)" -match '(?i)(^|\\)Everyone$|Anonymous' -and
                    "$($Entry.AccessRight)" -match '^(Full|Change)$') {

                    "[WARNING] Share '$($Share.Name)' grants $($Entry.AccessRight) access to $($Entry.AccountName)."
                }
            }
        }
        catch {
            "[UNKNOWN] Could not read the access list of share '$($Share.Name)'."
        }
    }

    ""
    "[REVIEW] $($Custom.Count) custom share(s) exist. Remove any you do not recognize."
    "[INFO] The print$ share is normal when printers are installed."
}

# ============================================================
# 26. STARTUP PROGRAMS
# ============================================================

Invoke-Check "26. Startup programs (Run keys and Startup folders)" {

    $RunKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    )

    $Pattern = '(?i)\\AppData\\Local\\Temp\\|\\Users\\Public\\|\\Downloads\\|-encodedcommand|-enc\s|FromBase64String|\bmshta\.exe\b|\bwscript\.exe\b|\bcscript\.exe\b|\bregsvr32\.exe\b|-w(indowstyle)?\s+hidden'

    $StartTotal = 0
    $StartReview = 0

    foreach ($Key in $RunKeys) {

        if (-not (Test-Path -LiteralPath $Key)) {
            continue
        }

        $Props = @(
            (Get-ItemProperty -LiteralPath $Key -ErrorAction SilentlyContinue).PSObject.Properties |
                Where-Object { $_.Name -notmatch '^PS' }
        )

        foreach ($Prop in $Props) {

            $StartTotal++
            $Cmd = Protect-Text ([string]$Prop.Value)

            "Key: $Key"
            "Name: $($Prop.Name)"
            "Command: $Cmd"

            if ($Cmd -match $Pattern) {
                $StartReview++
                "[REVIEW] Startup command matches a suspicious pattern."
            }

            ""
        }
    }

    $Folders = @(
        (Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup"),
        (Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\StartUp")
    )

    foreach ($Folder in $Folders) {

        if (-not (Test-Path -LiteralPath $Folder)) {
            continue
        }

        $Files = @(
            Get-ChildItem -LiteralPath $Folder -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -ne "desktop.ini" }
        )

        foreach ($File in $Files) {

            $StartTotal++

            "Startup folder: $Folder"
            "File: $($File.Name)"
            "Modified: $($File.LastWriteTime)"

            if ($File.Extension -match '(?i)^\.(bat|cmd|vbs|vbe|js|jse|wsf|ps1|hta|scr)$') {
                $StartReview++
                "[REVIEW] Script file in a Startup folder."
            }

            ""
        }
    }

    "Total startup entries: $StartTotal"

    if ($StartReview -eq 0) {
        "[INFO] No startup entries matched the suspicious patterns."
    }
    else {
        "[WARNING] $StartReview startup entries require manual review."
    }

    "[INFO] Scheduled tasks are covered in section 22; services in section 16."
}

# ============================================================
# SAVE REPORT
# ============================================================

$script:CurrentSection = "Summary"

Add-Line ""
Add-Line "============================================================"
Add-Line "AUDIT COMPLETED"
Add-Line "============================================================"

$WarnCount = @($script:AuditFindings | Where-Object { $_ -match '\[WARNING\]' }).Count
$ReviewCount = @($script:AuditFindings | Where-Object { $_ -match '\[REVIEW\]' }).Count
$UnknownCount = @($script:AuditFindings | Where-Object { $_ -match '\[UNKNOWN\]' }).Count

$SummaryLines = New-Object System.Collections.Generic.List[string]
[void]$SummaryLines.Add("")
[void]$SummaryLines.Add("============================================================")
[void]$SummaryLines.Add("SUMMARY: WARNING=$WarnCount  REVIEW=$ReviewCount  UNKNOWN=$UnknownCount")
[void]$SummaryLines.Add("============================================================")

if ($script:AuditFindings.Count -eq 0) {
    [void]$SummaryLines.Add("[OK] No warnings, review items or unknowns.")
}
else {
    foreach ($Finding in $script:AuditFindings) {
        [void]$SummaryLines.Add("  " + $Finding)
    }

    [void]$SummaryLines.Add("")
    [void]$SummaryLines.Add("[INFO] Format: section :: finding. Details are in the sections below.")
    [void]$SummaryLines.Add("[INFO] Findings are leads to check, not proof of compromise.")
}

$Report.InsertRange($SummaryInsertIndex, $SummaryLines)

Write-Host ""
foreach ($SummaryLine in $SummaryLines) {
    if ($SummaryLine -match '\[WARNING\]') {
        Write-Host $SummaryLine -ForegroundColor Yellow
    }
    elseif ($SummaryLine -match '\[(REVIEW|UNKNOWN)\]') {
        Write-Host $SummaryLine -ForegroundColor Cyan
    }
    else {
        Write-Host $SummaryLine
    }
}

try {
    $Report | Set-Content -LiteralPath $ReportFile -Encoding UTF8
    Write-Host ""
    Write-Host "Report saved to: $ReportFile" -ForegroundColor Green
}
catch {
    Write-Host ""
    Write-Host "[ERROR] Could not save report: $($_.Exception.Message)" -ForegroundColor Red
}
