<#
.SYNOPSIS
    Wrapper script for code signing using Azure Key Vault certificates
.EXAMPLES
    # Direct invocation (recommended)
    & "C:\Path\To\CodeSignWrapper.ps1" -Path C:\Build\MyApp.exe

    # From repository folder
    pwsh -File .\CodeSignWrapper.ps1 -Path .\bin\app.exe

    # Dot-sourcing ONLY if you need the helper functions in your session (not required just to sign)
    . .\CodeSignWrapper.ps1
    Sign-Code (future exported functions if any)

    IMPORTANT:
    Do NOT invoke with:
        . { \TeledyneDevOps\CodeSigning\CodeSignWrapper.ps1 }
    That syntax creates a script block; the bare path (starting with backslash) is not resolved and causes:
        The term '\TeledyneDevOps\CodeSigning\CodeSignWrapper.ps1' is not recognized...
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Position=0)] [string]$Path,
    [string[]]$Include = @("*.ps1","*.psm1","*.psd1","*.dll","*.exe","*.zip","*.msi","*.msix","*.appx","*.cab","*.sys","*.vbs","*.js","*.wsf","*.cat","*.msp","*.jar","*.container","*.tar","*.oci","*.dat","*.msm"),
    [string[]]$Exclude = @(),
    [string]$ConfigPath = "$PSScriptRoot\config.json",
    [string]$LogDir = "$PSScriptRoot\logs",
    [string]$CertificateName,
    [switch]$Recurse,
    [switch]$Force,
    [switch]$UpdateTools,
    [string]$SIEMServer = "us1-nslb-ecs.tdy.teledyne.com",
    [int]$SIEMPort = 11818,
    [ValidateSet("TCP","UDP")] [string]$SIEMProtocol = "TCP",
    [bool]$EnableSIEM = $true,
    [switch]$RememberCertificate,
    [switch]$UseContainerSigning,
    [switch]$Help,
    [switch]$Version,
    [switch]$DryRun,

    # Continue processing files even if some fail to sign
    [Parameter(Mandatory=$false)]
    [switch]$ContinueOnError = $true
)

Begin {
    $ErrorActionPreference = "Stop"
    Set-StrictMode -Version Latest
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $ConfigPath  = Join-Path $scriptDir "config.json"
    $LogDir      = Join-Path $scriptDir "logs"
    $credMgrPath = Join-Path $scriptDir "CredentialManager.ps1"
    $lastUsedCertPath = Join-Path $scriptDir "lastcert.txt"
    if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
    $LogFile = Join-Path $LogDir ("signing_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))

    function Show-ErrorLogSummary {
        # Check for recent error log files (within last 5 minutes)
        $cutoffTime = (Get-Date).AddMinutes(-5)
        $recentErrorLogs = Get-ChildItem -Path $LogDir -Filter "*_error_*.txt" -ErrorAction SilentlyContinue | 
                           Where-Object { $_.LastWriteTime -ge $cutoffTime } | 
                           Sort-Object LastWriteTime -Descending
        
        if ($recentErrorLogs) {
            Write-Host "`n" + ("=" * 60) -ForegroundColor Red
            Write-Host "ERROR LOG SUMMARY" -ForegroundColor Red
            Write-Host ("=" * 60) -ForegroundColor Red
            Write-Host "The following error logs were generated during this signing operation:" -ForegroundColor Yellow
            Write-Host ""
            
            foreach ($logFile in $recentErrorLogs) {
                Write-Host "  • $($logFile.Name)" -ForegroundColor White
                Write-Host "    Created: $($logFile.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray
                Write-Host "    Size: $([math]::Round($logFile.Length / 1KB, 2)) KB" -ForegroundColor Gray
                Write-Host "    Path: $($logFile.FullName)" -ForegroundColor Gray
                Write-Host ""
            }
            
            Write-Host "These files contain detailed error information including:" -ForegroundColor Yellow
            Write-Host "  • Complete command-line arguments used" -ForegroundColor Gray
            Write-Host "  • Full standard output and error streams" -ForegroundColor Gray
            Write-Host "  • Exit codes and timestamps" -ForegroundColor Gray
            Write-Host ""
            Write-Host "Please review these files for detailed troubleshooting information." -ForegroundColor Yellow
            Write-Host ("=" * 60) -ForegroundColor Red
        }
    }


    # Enhanced SIEM logging for better visibility
    function Send-ToSIEM {
        param(
            [string]$Message,
            [string]$Level = "INFO",
            [string]$EventType = "CodeSigning",
            [string]$Action = "",
            [hashtable]$Properties = @{ },
            [switch]$ForceSend = $false
        )
        
        # Only send to SIEM if explicitly forced or if EnableSIEM is true
        # This allows us to collect logs but only send the final summary
        if ((-not $EnableSIEM) -and (-not $ForceSend)) { return }
        
        try {
            # Create a structured log event with Exabeam expected fields
            $eventProperties = @{
                # Standard Exabeam fields based on your screenshot
                "activity" = $EventType
                "activity_type" = "code-signing"  
                "landscape" = "endpoint security"
                # Improved mapping of log levels to outcomes
                "outcome" = switch ($Level) {
                    "SUCCESS" { "success" }
                    "ERROR" { "failure" }
                    "WARN" { "warning" }
                    "INFO" { "informational" }
                    default { "informational" }
                }
                "platform" = "Windows"
                "product" = "CodeSignWrapper"
                "product_category" = "security operation"
                "subject" = $Action
                "time" = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                "vendor" = "Teledyne"
                "src_ip" = [string](Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne "127.0.0.1" } | Select-Object -First 1 -ExpandProperty IPAddress)
                "user" = $env:USERNAME
                "host" = $env:COMPUTERNAME
                "Message" = $Message
            }
            
            # Add any additional properties 
            foreach ($key in $Properties.Keys) {
                $eventProperties[$key] = $Properties[$key]
            }
            
            # Convert to JSON for better parsing in SIEM
            $jsonEvent = $eventProperties | ConvertTo-Json -Compress
            
            if ($SIEMProtocol -eq "TCP") {
                $client = New-Object System.Net.Sockets.TcpClient
                $client.Connect($SIEMServer, $SIEMPort)
                $stream = $client.GetStream()
                $writer = New-Object System.IO.StreamWriter($stream)
                $writer.WriteLine($jsonEvent)
                $writer.Flush()
                $writer.Close()
                $stream.Close()
                $client.Close()
            }
            else { # UDP
                $endpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($SIEMServer), $SIEMPort)
                $udpClient = New-Object System.Net.Sockets.UdpClient
                $bytes = [System.Text.Encoding]::ASCII.GetBytes($jsonEvent)
                $udpClient.Send($bytes, $bytes.Length, $endpoint)
                $udpClient.Close()
            }
        }
        catch {
            # Log error locally but don't fail the main operation
            $errorMessage = "Failed to send to SIEM: $_"
            Add-Content -Path $LogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [ERROR] $errorMessage"
            Write-Host $errorMessage -ForegroundColor Red
        }
    }
    
    function Write-Log {
        <#
        .SYNOPSIS
            Writes formatted log messages to both file and console, and SIEM if enabled
        .DESCRIPTION
            Handles logging of messages with timestamps and different severity levels,
            writing to a log file, optionally to the console with color coding,
            and to SIEM if enabled.
        .PARAMETER Message
            The message to log
        .PARAMETER Level
            The severity level (INFO, WARN, ERROR, SUCCESS)
        .PARAMETER Console
            Switch to indicate if message should also be written to console
        .PARAMETER Properties
            Additional properties to include in SIEM logs as a hashtable
        #>
        param(
            [string]$Message,
            [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS')]
            [string]$Level = "INFO",
            [switch]$Console,
            [string]$EventType = "CodeSigning",
            [string]$Action = "",
            [hashtable]$Properties = @{ },
            [switch]$SendToSIEM = $false
        )
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logMessage = "$timestamp [$Level] $Message"
        
        # Write to log file
        Add-Content -Path $LogFile -Value $logMessage
        
        # Write to console if requested or for important messages
        if ($Console -or $Level -in @('ERROR', 'SUCCESS') -or $VerbosePreference -eq 'Continue') {
            $color = switch ($Level) {
                'ERROR' { 'Red' }
                'WARN'  { 'Yellow' }
                'SUCCESS' { 'Green' }
                default { 'Gray' }
            }
            Write-Host $logMessage -ForegroundColor $color
        }
        
        # Only send to SIEM if explicitly requested now - we'll do a comprehensive send at the end
        if ($SendToSIEM) {
            Send-ToSIEM -Message $Message -Level $Level -EventType $EventType -Action $Action -Properties $Properties
        }
    }

    if ($Help){
@"
Usage:
  & .\CodeSignWrapper.ps1 -Path <file|dir> [options]

Correct Invocation Examples:
  & 'C:\GitRepo\CodeSigning\CodeSignWrapper.ps1' -Path C:\Temp\Test.exe
  pwsh -File .\CodeSignWrapper.ps1 -Path .\dist -Recurse
  .\CodeSignWrapper.ps1 -Path C:\Pkg\setup.msi

Avoid (incorrect):
  . { \TeledyneDevOps\CodeSigning\CodeSignWrapper.ps1 }
    (The braces create a script block and the leading backslash is not a valid drive-qualified path.)

Options:
  -Include / -Exclude
  -CertificateName <name>  (-RememberCertificate to persist)
  -Recurse
  -Force
  -UpdateTools
  -UseContainerSigning
  -DryRun
  -ContinueOnError         Continue processing files even if some fail (default: true)
  -Help / -Version

Use -DryRun to preview without signing.
"@ | Write-Host; exit 0
    }

    if ($Version){
        Write-Host "CodeSignWrapper.ps1 version 1.4.0"
        Write-Host "AzureSignTool v6.0.1"
        Write-Host "Cosign v2.2.3"
        exit 0
    }

    # Ensure script can find its dependencies regardless of where it's run from
    $scriptPath = $MyInvocation.MyCommand.Path
    $scriptDir = Split-Path -Parent $scriptPath
    
    # Update paths to be relative to script location
    $ConfigPath = Join-Path $scriptDir "config.json"
    $LogDir = Join-Path $scriptDir "logs"
    $credentialManagerPath = Join-Path $scriptDir "CredentialManager.ps1"
    $lastUsedCertPath = Join-Path $scriptDir "lastcert.txt"
    
    # Create directories if they don't exist
    if (-not (Test-Path $LogDir)) {
        New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    }

    # Initialize log file with timestamp
    $LogFile = Join-Path $LogDir ("signing_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))

    # Enhanced SIEM logging for better visibility
    function Send-ToSIEM {
        param(
            [string]$Message,
            [string]$Level = "INFO",
            [string]$EventType = "CodeSigning",
            [string]$Action = "",
            [hashtable]$Properties = @{ },
            [switch]$ForceSend = $false
        )
        
        # Only send to SIEM if explicitly forced or if EnableSIEM is true
        # This allows us to collect logs but only send the final summary
        if ((-not $EnableSIEM) -and (-not $ForceSend)) { return }
        
        try {
            # Create a structured log event with Exabeam expected fields
            $eventProperties = @{
                # Standard Exabeam fields based on your screenshot
                "activity" = $EventType
                "activity_type" = "code-signing"  
                "landscape" = "endpoint security"
                # Improved mapping of log levels to outcomes
                "outcome" = switch ($Level) {
                    "SUCCESS" { "success" }
                    "ERROR" { "failure" }
                    "WARN" { "warning" }
                    "INFO" { "informational" }
                    default { "informational" }
                }
                "platform" = "Windows"
                "product" = "CodeSignWrapper"
                "product_category" = "security operation"
                "subject" = $Action
                "time" = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                "vendor" = "Teledyne"
                "src_ip" = [string](Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne "127.0.0.1" } | Select-Object -First 1 -ExpandProperty IPAddress)
                "user" = $env:USERNAME
                "host" = $env:COMPUTERNAME
                "Message" = $Message
            }
            
            # Add any additional properties 
            foreach ($key in $Properties.Keys) {
                $eventProperties[$key] = $Properties[$key]
            }
            
            # Convert to JSON for better parsing in SIEM
            $jsonEvent = $eventProperties | ConvertTo-Json -Compress
            
            if ($SIEMProtocol -eq "TCP") {
                $client = New-Object System.Net.Sockets.TcpClient
                $client.Connect($SIEMServer, $SIEMPort)
                $stream = $client.GetStream()
                $writer = New-Object System.IO.StreamWriter($stream)
                $writer.WriteLine($jsonEvent)
                $writer.Flush()
                $writer.Close()
                $stream.Close()
                $client.Close()
            }
            else { # UDP
                $endpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($SIEMServer), $SIEMPort)
                $udpClient = New-Object System.Net.Sockets.UdpClient
                $bytes = [System.Text.Encoding]::ASCII.GetBytes($jsonEvent)
                $udpClient.Send($bytes, $bytes.Length, $endpoint)
                $udpClient.Close()
            }
        }
        catch {
            # Log error locally but don't fail the main operation
            $errorMessage = "Failed to send to SIEM: $_"
            Add-Content -Path $LogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [ERROR] $errorMessage"
            Write-Host $errorMessage -ForegroundColor Red
        }
    }
    
    function Write-Log {
        <#
        .SYNOPSIS
            Writes formatted log messages to both file and console, and SIEM if enabled
        .DESCRIPTION
            Handles logging of messages with timestamps and different severity levels,
            writing to a log file, optionally to the console with color coding,
            and to SIEM if enabled.
        .PARAMETER Message
            The message to log
        .PARAMETER Level
            The severity level (INFO, WARN, ERROR, SUCCESS)
        .PARAMETER Console
            Switch to indicate if message should also be written to console
        .PARAMETER Properties
            Additional properties to include in SIEM logs as a hashtable
        #>
        param(
            [string]$Message,
            [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS')]
            [string]$Level = "INFO",
            [switch]$Console,
            [string]$EventType = "CodeSigning",
            [string]$Action = "",
            [hashtable]$Properties = @{ },
            [switch]$SendToSIEM = $false
        )
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logMessage = "$timestamp [$Level] $Message"
        
        # Write to log file
        Add-Content -Path $LogFile -Value $logMessage
        
        # Write to console if requested or for important messages
        if ($Console -or $Level -in @('ERROR', 'SUCCESS') -or $VerbosePreference -eq 'Continue') {
            $color = switch ($Level) {
                'ERROR' { 'Red' }
                'WARN'  { 'Yellow' }
                'SUCCESS' { 'Green' }
                default { 'Gray' }
            }
            Write-Host $logMessage -ForegroundColor $color
        }
        
        # Only send to SIEM if explicitly requested now - we'll do a comprehensive send at the end
        if ($SendToSIEM) {
            Send-ToSIEM -Message $Message -Level $Level -EventType $EventType -Action $Action -Properties $Properties
        }
    }

    # Check for required files
    $requiredFiles = @(
        @{Name = "CredentialManager.ps1"; Path = $credentialManagerPath},
        @{Name = "AzureSignTool-x64.exe"; Path = (Join-Path $scriptDir "AzureSignTool-x64.exe")}
    )

    foreach ($file in $requiredFiles) {
        if (-not (Test-Path $file.Path)) {
            if ($file.Name -eq "CredentialManager.ps1") {
                Write-Host "Required file 'CredentialManager.ps1' not found in script directory." -ForegroundColor Red
                Write-Host "Download it from: https://github.com/TeledyneDevOps/CodeSigning" -ForegroundColor Yellow
                exit 1
            }
            throw "Required file '$($file.Name)' not found in script directory. Please ensure all components are extracted together."
        }
    }

    # Check if $LogDir is writable
    try {
        $testLog = Join-Path $LogDir "write_test.txt"
        "test" | Out-File $testLog
        Remove-Item $testLog -Force
    } catch {
        Write-Host "Log directory '$LogDir' is not writable. Please check permissions." -ForegroundColor Red
        exit 1
    }

    # Load CredentialManager
    . $credentialManagerPath

    # Initialize or load config with better error handling
    if (-not (Test-Path $ConfigPath)) {
        try {
            @{
                KeyVaultUrl = "https://itss-managed-certs.vault.azure.net/"
                DefaultCertificateName = "ITSS-Code-Signing"
                ClientId = "c699b1cf-73bd-4896-8dd2-74ea7d99dc60"
                TenantId = "e324592a-2653-45c7-9bfc-597c36917127"
                TimestampServer = "http://timestamp.digicert.com"
            } | ConvertTo-Json | Set-Content $ConfigPath -ErrorAction Stop
            Write-Log "Created default configuration at $ConfigPath" -Console
        }
        catch {
            throw "Failed to create config file at '$ConfigPath': $_"
        }
    }

    try {
        # Read the raw content of the config file first for validation
        $rawConfig = Get-Content $ConfigPath -Raw -ErrorAction Stop
        
        # Look for common JSON errors before parsing
        if ($rawConfig.StartsWith("//")) {
            throw "JSON files cannot contain comments. Remove any comment lines starting with // from the config file."
        }
        
        if ($rawConfig -match '(^|\s)//') {
            throw "JSON files cannot contain comments. Remove any comment lines containing // from the config file."
        }
        
        # Now try to parse as JSON
        try {
            $config = $rawConfig | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            # Provide a more helpful error message
            if ($_.Exception.Message -match "Invalid JSON primitive") {
                throw "Invalid JSON format in '$ConfigPath'. JSON files cannot contain comments or trailing commas. Error: $_"
            }
            else {
                throw "Failed to parse JSON from '$ConfigPath': $_"
            }
        }
        
        # Validate required fields
        $requiredFields = @("KeyVaultUrl", "DefaultCertificateName", "ClientId", "TenantId", "TimestampServer")
        $missingFields = $requiredFields.Where({ -not $config.PSObject.Properties.Name.Contains($_) })
        
        if ($missingFields.Count -gt 0) {
            throw "Config file is missing required fields: $($missingFields -join ', ')"
        }
    }
    catch {
        throw "Failed to load config from '$ConfigPath': $_"
    }

    # Track statistics
    $stats = @{
        Total = 0
        Success = 0
        Failed = 0
        Skipped = 0
    }
    
    # Add array to track all signed files with details
    $signedFilesDetails = @()
    
    function Get-AzureSignTool {
        <#
        .SYNOPSIS
            Downloads or returns path to AzureSignTool executable
        .DESCRIPTION
            Manages the AzureSignTool executable, downloading it if not present
            or returning the path if it exists. Handles backup/restore during updates.
        .OUTPUTS
            String containing the path to AzureSignTool-x64.exe
        .NOTES
            The tool is downloaded from GitHub if not present or if Force is specified.
            A backup is created during updates to ensure recoverability.
        #>
        $toolPath = "$PSScriptRoot\AzureSignTool-x64.exe"
        if ((Test-Path $toolPath) -and (-not $Force)) { return $toolPath }

        try {
            Write-Log "Downloading Azure Sign Tool..." -Console
            # Always use the x64 version as specified
            $url = "https://github.com/vcsjones/AzureSignTool/releases/download/v6.0.1/AzureSignTool-x64.exe"
            
            if (Test-Path $toolPath) { Copy-Item $toolPath "$toolPath.backup" -Force }
            
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $url -OutFile $toolPath
            if (Test-Path "$toolPath.backup") { Remove-Item "$toolPath.backup" -Force }
            Write-Log "Azure Sign Tool v6.0.1 downloaded successfully" -Console
            return $toolPath
        }
        catch {
            Write-Log $_.Exception.Message -Level ERROR -Console
            if (Test-Path "$toolPath.backup") { 
                Move-Item "$toolPath.backup" $toolPath -Force
                Write-Log "Restored previous version" -Level WARN
            }
            throw
        }
    }

    function Get-Cosign {
        <#
        .SYNOPSIS
            Downloads or returns path to Cosign executable
        .DESCRIPTION
            Manages the Cosign executable, downloading it if not present
            or returning the path if it exists. Used for container signing.
        .OUTPUTS
            String containing the path to cosign.exe
        .NOTES
            The tool is downloaded from GitHub if not present or if Force is specified.
            A backup is created during updates to ensure recoverability.
            Cosign v2.2.3 is used for container signing with Azure Key Vault integration.
        #>
        $toolPath = "$PSScriptRoot\cosign.exe"
        if ((Test-Path $toolPath) -and (-not $Force)) { return $toolPath }
        
        try {
            Write-Log "Downloading Cosign tool for container signing..." -Console
            # Download latest version of Cosign
            $url = "https://github.com/sigstore/cosign/releases/download/v2.2.3/cosign-windows-amd64.exe"
            
            if (Test-Path $toolPath) { Copy-Item $toolPath "$toolPath.backup" -Force }
            
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $url -OutFile $toolPath
            if (Test-Path "$toolPath.backup") { Remove-Item "$toolPath.backup" -Force }
            Write-Log "Cosign v2.2.3 downloaded successfully" -Console
            return $toolPath
        }
        catch {
            Write-Log $_.Exception.Message -Level ERROR -Console
            if (Test-Path "$toolPath.backup") { 
                Move-Item "$toolPath.backup" $toolPath -Force
                Write-Log "Restored previous version" -Level WARN
            }
            throw
        }
    }

    function Test-FileSignable {
        <#
        .SYNOPSIS
            Tests if a file can and should be signed
        .DESCRIPTION
            Checks if a file meets all criteria for signing:
            - Exists and is not empty
            - Matches include patterns
            - Doesn't match exclude patterns
            - Is a supported file type for signing
            - Not already signed (unless Force is specified)
        .PARAMETER FilePath
            The path to the file to test
        .OUTPUTS
            Boolean indicating if the file should be signed
        .NOTES
            Special handling is included for container files and archives.
            Already signed files are skipped unless Force is specified.
        #>
        param([string]$FilePath)
        
        try {
            # Check if file exists and is not empty
            if (-not (Test-Path $FilePath -PathType Leaf)) { return $false }
            $fileObj = Get-Item $FilePath
            if ($fileObj.Length -eq 0) { return $false }
            
            # Check if file matches include patterns
            $fileName = Split-Path $FilePath -Leaf
            $included = $false
            foreach ($pattern in $Include) {
                if ($fileName -like $pattern) {
                    $included = $true
                    break
                }
            }
            if (-not $included) { return $false }
            
            # Check if file matches exclude patterns
            foreach ($pattern in $Exclude) {
                if ($fileName -like $pattern) { return $false }
            }
            
            # Handle special case for container images and OCI artifacts
            $extension = [System.IO.Path]::GetExtension($fileName).ToLower()
            if ($extension -in @('.container', '.tar', '.oci') -or $UseContainerSigning) {
                # Container files or references need special handling with Cosign
                Write-Log "Detected container artifact for Cosign signing" -Level INFO -Console
                return $true
            }
            
            # Handle special case for .zip and archive files - they must be PE files or valid scripts
            if ($extension -in @('.zip', '.msix', '.appx', '.cab', '.jar')) {
                # We can't sign regular ZIP files directly, but can sign some container formats
                if ($extension -eq '.zip') {
                    Write-Log "Warning: Standard ZIP files cannot be directly signed with Authenticode." -Level WARN -Console
                    Write-Log "Only PE files inside ZIP archives can be signed (after extraction)." -Level WARN -Console
                    return $false # Skip ZIP files by default
                }
                else {
                    # Other container formats like MSIX can be signed
                    Write-Log "Note: $extension file will be signed as a container. Contents won't be individually signed." -Level INFO -Console
                }
            }
            
            # If Force is true or file isn't signed, allow signing
            try {
                # Not all files support Get-AuthenticodeSignature, so wrap in try/catch
                $sig = Get-AuthenticodeSignature $FilePath -ErrorAction SilentlyContinue
                if ($null -ne $sig -and -not $Force -and $sig.Status -eq "Valid") {
                    # Enhanced logging for already signed files
                    $fileObj = Get-Item $FilePath
                    $fileMetadata = @{
                        "FileName" = $fileObj.Name
                        "FilePath" = $fileObj.FullName
                        "FileSize" = $fileObj.Length
                        "FileType" = $fileObj.Extension.TrimStart('.')
                        "SignatureStatus" = $sig.Status.ToString()
                    }
                    
                    # Add certificate details if available
                    if ($sig.SignerCertificate -ne $null) {
                        $fileMetadata["CertificateSubject"] = $sig.SignerCertificate.Subject
                        $fileMetadata["CertificateIssuer"] = $sig.SignerCertificate.Issuer
                        $fileMetadata["CertificateExpiry"] = $sig.SignerCertificate.NotAfter.ToString()
                        $fileMetadata["CertificateThumbprint"] = $sig.SignerCertificate.Thumbprint
                    }
                    
                    Write-Log -Message "File already signed: $FilePath" -Level INFO -Console -EventType "CodeSigning" -Action "AlreadySigned" -Properties $fileMetadata
                    
                    return $false
                }
                
                return $true
            }
            catch {
                # If we can't check signature status, assume file is signable if it matched our patterns
                Write-Log "Unable to verify signature on $FilePath. Will attempt to sign based on extension." -Level WARN -Console
                return $true
            }
        }
        catch {
            # Enhanced error logging with structured data
            $errorMetadata = @{
                "EventType" = "CodeSigning" 
                "Action" = "Error"
                "FilePath" = $FilePath
                "FileName" = (Split-Path $FilePath -Leaf)
                "ErrorMessage" = $_.Exception.Message
            }
            Write-Log "Error checking file $FilePath : $_" -Level ERROR -Properties $errorMetadata
            return $false
        }
    }

    function Get-LastUsedCertificate {
        if (Test-Path $lastUsedCertPath) {
            return Get-Content $lastUsedCertPath -ErrorAction SilentlyContinue
        }
        return $null
    }
    
    function Set-LastUsedCertificate {
        param([string]$CertName)
        
        if ($RememberCertificate -and -not [string]::IsNullOrWhiteSpace($CertName)) {
            $CertName | Out-File $lastUsedCertPath -Force
        }
    }

    # Enhanced certificate selection with visual menu
    function Select-Certificate {
        # Get stored certificates first
        $storedCerts = @(cmdkey /list | Select-String "CodeSigning_" | ForEach-Object {
            $_.ToString() -replace ".*CodeSigning_", ""
        })
        
        $lastUsed = Get-LastUsedCertificate
        
        # Create options array with padding for better display
        $options = @()
        
        # Fix: Handle empty $storedCerts collection
        $storedCertMaxLength = 0
        if ($storedCerts.Count -gt 0) {
            $storedCertMaxLength = ($storedCerts | Measure-Object -Property Length -Maximum).Maximum
        }
        
        # Fix: Chain Math::Max calls to handle multiple values
        $maxLength = [Math]::Max(
            [Math]::Max(
                $config.DefaultCertificateName.Length,
                $storedCertMaxLength
            ),
            [Math]::Max(
                "Enter different name".Length,
                "Manage stored certificates".Length
            )
        ) + 5
        
        # Replace Unicode box drawing with ASCII characters
        Write-Host "`n+$("-" * ($maxLength + 6))+" -ForegroundColor Cyan
        Write-Host "| Certificate Selection Menu  |" -ForegroundColor Cyan
        Write-Host "+$("-" * ($maxLength + 6))+" -ForegroundColor Cyan
        
        # Default certificate option
        $defaultLabel = "$($config.DefaultCertificateName) (Default)"
        if ($config.DefaultCertificateName -eq $lastUsed) {
            $defaultLabel += " [Last Used]"
        }
        Write-Host "  [1] " -ForegroundColor Yellow -NoNewline
        Write-Host $defaultLabel
        $options += $config.DefaultCertificateName

        # Last used certificate if different from default
        if ($lastUsed -and $lastUsed -ne $config.DefaultCertificateName) {
            Write-Host "  [2] " -ForegroundColor Yellow -NoNewline
            Write-Host "$lastUsed [Last Used]"
            $options += $lastUsed
            $startIdx = 3
        } else {
            $startIdx = 2
        }
        
        # Stored certificates
        $certIdx = $startIdx
        foreach ($cert in $storedCerts) {
            # Skip if already listed as default or last used
            if ($cert -eq $config.DefaultCertificateName -or $cert -eq $lastUsed) {
                continue
            }
            Write-Host "  [$certIdx] " -ForegroundColor Yellow -NoNewline
            Write-Host $cert
            $options += $cert
            $certIdx++
        }
        
        # Additional options
        Write-Host "  [$certIdx] " -ForegroundColor Yellow -NoNewline
        Write-Host "Enter different name"
        $enterDiffIdx = $certIdx
        $certIdx++
        
        Write-Host "  [$certIdx] " -ForegroundColor Yellow -NoNewline
        Write-Host "Manage stored certificates" -ForegroundColor Cyan
        $manageIdx = $certIdx
        
        $choice = Read-Host "`nSelect option (1-$certIdx)"
        
        # Handle numeric choice
        if ([int]::TryParse($choice, [ref]$null)) {
            $choiceNum = [int]$choice
            
            # Direct certificate selection
            if ($choiceNum -ge 1 -and $choiceNum -lt $enterDiffIdx) {
                $selectedCert = $options[$choiceNum - 1]
                Set-LastUsedCertificate -CertName $selectedCert
                return $selectedCert
            }
            # Enter different name
            elseif ($choiceNum -eq $enterDiffIdx) {
                $inputName = Read-Host "Enter certificate name"
                if ([string]::IsNullOrWhiteSpace($inputName)) {
                    Write-Host "Using default certificate" -ForegroundColor Yellow
                    Set-LastUsedCertificate -CertName $config.DefaultCertificateName
                    return $config.DefaultCertificateName
                }
                
                # Prompt to store if this is a new certificate name
                if ($inputName -notin $storedCerts -and $inputName -ne $config.DefaultCertificateName) {
                    $saveChoice = Read-Host "Do you want to save this certificate name for future use? (Y/N)"
                    if ($saveChoice -eq 'Y') {
                        Save-CodeSigningCredential -CertificateName $inputName -Secret (New-Object SecureString)
                    }
                }
                
                Set-LastUsedCertificate -CertName $inputName
                return $inputName
            }
            # Manage certificates
            elseif ($choiceNum -eq $manageIdx) {
                Show-CertificateManager
                return (Select-Certificate) # Recursive call for new selection
            }
        }
        
        # Default fallback
        Write-Host "Invalid selection. Using default certificate." -ForegroundColor Yellow
        Set-LastUsedCertificate -CertName $config.DefaultCertificateName
        return $config.DefaultCertificateName
    }
    
    function Show-CertificateManager {
        $storedCerts = @(cmdkey /list | Select-String "CodeSigning_" | ForEach-Object {
            $_.ToString() -replace ".*CodeSigning_", ""
        })
        
        # Replace Unicode box drawing with ASCII characters
        Write-Host "`n+$("-" * 30)+" -ForegroundColor Cyan
        Write-Host "| Certificate Management  |" -ForegroundColor Cyan
        Write-Host "+$("-" * 30)+" -ForegroundColor Cyan
        Write-Host "  [1] " -ForegroundColor Yellow -NoNewline
        Write-Host "List stored certificates"
        Write-Host "  [2] " -ForegroundColor Yellow -NoNewline
        Write-Host "Remove stored certificate"
        Write-Host "  [3] " -ForegroundColor Yellow -NoNewline
        Write-Host "Back to certificate selection"
        
        $mgmtChoice = Read-Host "`nSelect option (1-3)"
        
        switch ($mgmtChoice) {
            "1" {
                # Replace Unicode box drawing with ASCII characters
                Write-Host "`n+ Stored Certificates +" -ForegroundColor Cyan
                if ($storedCerts) {
                    foreach ($cert in $storedCerts) {
                        Write-Host "  - $cert"
                    }
                } else {
                    Write-Host "  (No stored certificates)" -ForegroundColor Gray
                }
                
                Write-Host "`nPress Enter to continue..." -ForegroundColor Yellow
                Read-Host | Out-Null
                return
            }
            "2" {
                if ($storedCerts) {
                    Write-Host "`nSelect certificate to remove:" -ForegroundColor Yellow
                    for ($i = 0; $i -lt $storedCerts.Count; $i++) {
                        Write-Host "  [$($i + 1)] $($storedCerts[$i])"
                    }
                    
                    $removeChoice = Read-Host "`nEnter number (or 'C' to cancel)"
                    
                    if ($removeChoice -ne 'C' -and [int]::TryParse($removeChoice, [ref]$null)) {
                        $index = [int]$removeChoice - 1
                        if ($index -ge 0 -and $index -lt $storedCerts.Count) {
                            Remove-CodeSigningCredential -CertificateName $storedCerts[$index]
                            Write-Host "Certificate removed successfully" -ForegroundColor Green
                        }
                    }
                } else {
                    Write-Host "`nNo stored certificates to remove." -ForegroundColor Yellow
                }
                
                Write-Host "`nPress Enter to continue..." -ForegroundColor Yellow
                Read-Host | Out-Null
                return
            }
            default {
                return
            }
        }
    }

    $azureSignToolPath = Get-AzureSignTool

    # Get Cosign if needed for container signing
    if ($UseContainerSigning) {
        $cosignPath = Get-Cosign
        Write-Log "Container signing enabled, using Cosign from: $cosignPath" -Console
    }

    # Modified certificate selection with management options
    if (-not $CertificateName) {
        $CertificateName = if ($env:AZURE_CERT_NAME) {
            $env:AZURE_CERT_NAME
        } else {
            Select-Certificate
        }
    }

    if ([string]::IsNullOrWhiteSpace($CertificateName)) {
        $CertificateName = $config.DefaultCertificateName
    }

    Write-Log "Using certificate: $CertificateName" -Console

    # Simplified Key Vault secret handling - always prompt
    if (-not $env:AZURE_KEYVAULT_SECRET) {
        $secureSecret = Read-Host "Enter Key Vault Secret" -AsSecureString
        $env:AZURE_KEYVAULT_SECRET = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureSecret)
        )
    }

    # Validate certificate and credentials before asking for file
    Write-Log "Validating configuration..." -Console
    $testArgs = @(
        "sign",
        "--verbose",
        "--continue-on-error",
        "--kvu", $config.KeyVaultUrl,
        "--kvc", $CertificateName,
        "--azure-key-vault-client-id", $config.ClientId,
        "--azure-key-vault-tenant-id", $config.TenantId,
        "--kvs", $env:AZURE_KEYVAULT_SECRET,
        "--timestamp-rfc3161", $config.TimestampServer,
        "--help",
        "--verbose"
    )

    $configTestResult = Start-Process -FilePath $azureSignToolPath -ArgumentList $testArgs -NoNewWindow -Wait -PassThru -RedirectStandardError "$LogDir\stderr.txt" -RedirectStandardOutput "$LogDir\stdout.txt"
    
    # Read both output streams before cleanup
    $configStdout = $null
    $configStderr = $null
    
    if (Test-Path "$LogDir\stdout.txt") {
        $configStdout = Get-Content "$LogDir\stdout.txt" -Raw
        Remove-Item "$LogDir\stdout.txt" -ErrorAction SilentlyContinue
    }
    
    if (Test-Path "$LogDir\stderr.txt") {
        $configStderr = Get-Content "$LogDir\stderr.txt" -Raw
        Remove-Item "$LogDir\stderr.txt" -ErrorAction SilentlyContinue
    }
    
    if ($configTestResult.ExitCode -ne 0 -or $configStderr) {
        Write-Host "Configuration validation failed!" -ForegroundColor Red
        Write-Host "Exit Code: $($configTestResult.ExitCode)" -ForegroundColor Red
        
        if ($configStderr) {
            Write-Host "Error Output:" -ForegroundColor Red
            Write-Host $configStderr -ForegroundColor Red
        }
        
        if ($configStdout) {
            Write-Host "Standard Output:" -ForegroundColor Yellow  
            Write-Host $configStdout -ForegroundColor Yellow
        }
        
        $configErrorData = @{
            "KeyVaultUrl" = $config.KeyVaultUrl
            "CertificateName" = $CertificateName
            "ExitCode" = $configTestResult.ExitCode
            "ErrorDetails" = $configStderr
            "StandardOutput" = $configStdout
        }
        
        Write-Log -Message "Configuration validation failed with exit code $($configTestResult.ExitCode)" -Level ERROR -Console -EventType "CodeSigning" -Action "ConfigValidationFailed" -Properties $configErrorData
        if ($configStderr) {
            Write-Log -Message "Error details: $configStderr" -Level ERROR -Console -EventType "CodeSigning" -Action "ConfigValidationFailed" -Properties $configErrorData
        }
        exit 1
    }
    
    $configSuccessData = @{
        "KeyVaultUrl" = $config.KeyVaultUrl
        "CertificateName" = $CertificateName
    }
    Write-Log -Message "Configuration validated successfully" -Level SUCCESS -Console -EventType "CodeSigning" -Action "ConfigValidationSuccess" -Properties $configSuccessData

    # Now prompt for file path if not provided using command-line input instead of GUI
    if (-not $Path) {
        $Path = Read-Host "Enter path to file or directory to sign"
        
        # If user entered empty path, exit gracefully
        if ([string]::IsNullOrWhiteSpace($Path)) {
            Write-Host "No path provided. Operation canceled." -ForegroundColor Yellow
            exit 0
        }
    }

    # Validate path
    if (-not (Test-Path $Path)) {
        throw "The specified path '$Path' does not exist"
    }
}

Process {
    try {
        # Modified certificate verification
        try {
            Write-Log "Verifying certificate '$CertificateName' in KeyVault..." -Console
            
            # Try to verify with quiet mode
            $testArgs = @(
                "sign",
                "--verbose",
                "--continue-on-error",
                "--kvu", $config.KeyVaultUrl,
                "--kvc", $CertificateName,
                "--azure-key-vault-client-id", $config.ClientId,
                "--azure-key-vault-tenant-id", $config.TenantId,
                "--kvs", $env:AZURE_KEYVAULT_SECRET,
                "--timestamp-rfc3161", $config.TimestampServer,
                "--help"
            )
            
            $testResult = Start-Process -FilePath $azureSignToolPath `
                -ArgumentList $testArgs `
                -NoNewWindow `
                -Wait `
                -PassThru `
                -RedirectStandardError "$LogDir\stderr.txt" `
                -RedirectStandardOutput "$LogDir\stdout.txt"

            # Read output files before cleanup
            $stdoutContent = $null
            $stderrContent = $null
            
            if (Test-Path "$LogDir\stdout.txt") {
                $stdoutContent = Get-Content "$LogDir\stdout.txt" -Raw
                Remove-Item "$LogDir\stdout.txt" -ErrorAction SilentlyContinue
            }
            
            if (Test-Path "$LogDir\stderr.txt") {
                $stderrContent = Get-Content "$LogDir\stderr.txt" -Raw
                Remove-Item "$LogDir\stderr.txt" -ErrorAction SilentlyContinue
            }
            
            if ($testResult.ExitCode -ne 0) {
                # Translate error code for validation failures
                # Handle both signed and unsigned representations
                $exitCodeUInt = if ($testResult.ExitCode -lt 0) {
                    # Convert negative signed int to unsigned int
                    [uint32]([uint32]::MaxValue + $testResult.ExitCode + 1)
                } else {
                    [uint32]$testResult.ExitCode
                }
                $errorCodeHex = "0x{0:X8}" -f $exitCodeUInt
                $validationErrorMsg = ""
                
                switch ($exitCodeUInt) {
                    0x9FFFB002 { $validationErrorMsg = "Azure Key Vault authentication failed or certificate not found" }
                    0x80070005 { $validationErrorMsg = "Access denied - check service principal permissions" }
                    0x80092009 { $validationErrorMsg = "Certificate '$CertificateName' not found in Key Vault" }
                    0x8009200A { $validationErrorMsg = "Certificate has expired" }
                    default { 
                        try {
                            $systemMsg = [System.ComponentModel.Win32Exception]::new($testResult.ExitCode).Message
                            if ($systemMsg -and $systemMsg -ne "Unknown error") {
                                $validationErrorMsg = $systemMsg
                            } else {
                                $validationErrorMsg = "Unknown validation error"
                            }
                        } catch {
                            $validationErrorMsg = "Unknown validation error"
                        }
                    }
                }
                
                # Display detailed validation error information
                Write-Host "Certificate validation failed!" -ForegroundColor Red
                Write-Host "Exit Code: $($testResult.ExitCode) ($errorCodeHex)" -ForegroundColor Red
                Write-Host "Description: $validationErrorMsg" -ForegroundColor Red
                Write-Host "Certificate: $CertificateName" -ForegroundColor Red
                Write-Host "Key Vault: $($config.KeyVaultUrl)" -ForegroundColor Red
                
                if ($stderrContent) {
                    Write-Host "Error Output:" -ForegroundColor Red
                    Write-Host $stderrContent -ForegroundColor Red
                } else {
                    Write-Host "Error Output: (No error output captured)" -ForegroundColor Yellow
                }
                
                if ($stdoutContent) {
                    Write-Host "Standard Output:" -ForegroundColor Yellow
                    Write-Host $stdoutContent -ForegroundColor Yellow
                } else {
                    Write-Host "Standard Output: (No output captured)" -ForegroundColor Yellow
                }
                
                # Provide specific troubleshooting advice
                Write-Host "Troubleshooting:" -ForegroundColor Cyan
                switch ($exitCodeUInt) {
                    0x9FFFB002 {
                        Write-Host "  • Verify certificate name: '$CertificateName'" -ForegroundColor Gray
                        Write-Host "  • Check Key Vault permissions for client ID: $($config.ClientId)" -ForegroundColor Gray
                        Write-Host "  • Ensure AZURE_KEYVAULT_SECRET is correct" -ForegroundColor Gray
                    }
                    default {
                        Write-Host "  • Verify certificate exists in Key Vault" -ForegroundColor Gray
                        Write-Host "  • Check service principal permissions" -ForegroundColor Gray
                        Write-Host "  • Ensure proper network access to Azure" -ForegroundColor Gray
                    }
                }
                
                $errorMessage = "AzureSignTool validation failed with exit code: $($testResult.ExitCode) ($errorCodeHex) - $validationErrorMsg"
                if ($stderrContent) {
                    $errorMessage += ". Error details: $stderrContent"
                }
                
                throw $errorMessage
            }
            
            Write-Log "Azure Sign Tool validation successful" -Level SUCCESS -Console
            Write-Log "Proceeding with certificate: $CertificateName" -Level INFO -Console
        }
        catch {
            Write-Log "Tool validation failed: $_" -Level ERROR -Console
            Write-Log "Common issues:" -Level WARN -Console
            Write-Log " - Certificate name mismatch" -Level WARN -Console
            Write-Log " - Insufficient KeyVault permissions" -Level WARN -Console
            Write-Log " - Invalid Key Vault secret" -Level WARN -Console
            throw
        }

        # Get list of files to process with proper recursion and single file support (Ankit's improvement)
        if (Test-Path $Path -PathType Leaf) {
            # Single file
            $files = @()
            if (Test-FileSignable $Path) {
                $files += Get-Item $Path
            }
        } else {
            # Directory
            $files = @(Get-ChildItem -Path $Path -File -Recurse:$Recurse | 
                    Where-Object { Test-FileSignable $_.FullName })
        }
        
        $stats.Total = @($files).Count
        Write-Log "Found $($stats.Total) files to process" -Console
        
        # Add progress bar and counters
        $activity = "Signing files with certificate '$CertificateName'"
        $fileCounter = 0
        
        foreach ($file in $files) {
            try {
                $fileCounter++
                $progressPercent = [Math]::Min(($fileCounter / $stats.Total * 100), 100)
                
                # Update progress bar with detailed status
                $status = "Processing file $fileCounter of $($stats.Total): $($file.Name)"
                $statusDetail = "Success: $($stats.Success) | Failed: $($stats.Failed) | Skipped: $($stats.Skipped)"
                Write-Progress -Activity $activity -Status $status -PercentComplete $progressPercent -CurrentOperation $statusDetail
                
                Write-Log "Processing: $($file.FullName)" -Console
                
                # Get pre-signing certificate info if exists
                $preSig = Get-AuthenticodeSignature $file.FullName
                if ($preSig.Status -eq "Valid") {
                    Write-Log "File already signed by: $($preSig.SignerCertificate.Subject)" -Level WARN -Console
                }

                # Get file extension
                $extension = [System.IO.Path]::GetExtension($file.Name).ToLower()
                
                # Determine if special parameters are needed for this file type
                $additionalParams = @()
                
                # Handle container signing with Cosign
                if ($extension -in @('.container', '.tar', '.oci') -or $UseContainerSigning) {
                    # Download Cosign if not already available
                    if (-not $cosignPath) {
                        $cosignPath = Get-Cosign
                    }
                    
                    # Get container reference - either direct path or content of reference file
                    $containerRef = $file.FullName
                    if ($file.Extension -in @('.container', '.txt')) {
                        # If the file is a reference file, read the reference from its content
                        $containerRef = Get-Content $file.FullName -Raw
                    }
                    
                    Write-Log "Signing container: $containerRef with Cosign" -Console
                    
                    if ($PSCmdlet.ShouldProcess($file.FullName, "Sign Container")) {
                        # Set up environment variables required by Cosign for Azure Key Vault access
                        $env:COSIGN_AZUREKMS_RESOURCEID = $config.KeyVaultUrl
                        $env:COSIGN_AZUREKMS_CLIENTID = $config.ClientId
                        $env:COSIGN_AZUREKMS_TENANT = $config.TenantId
                        
                        try {
                            # Prepare Cosign command-line arguments - ensure proper quoting
                            $signArgs = @(
                                "sign",
                                "--key", "azurekms://$($config.KeyVaultUrl)/$CertificateName",
                                "`"$containerRef`""  # Ensure path is quoted to handle spaces
                            )
                            
                            # Execute Cosign with properly quoted arguments
                            $processStartInfo = New-Object System.Diagnostics.ProcessStartInfo
                            $processStartInfo.FileName = $cosignPath
                            $processStartInfo.Arguments = $signArgs -join ' '
                            $processStartInfo.RedirectStandardError = $true
                            $processStartInfo.RedirectStandardOutput = $true
                            $processStartInfo.UseShellExecute = $false
                            $processStartInfo.CreateNoWindow = $true
                            
                            $process = New-Object System.Diagnostics.Process
                            $process.StartInfo = $processStartInfo
                            [void]$process.Start()
                            $stderr = $process.StandardError.ReadToEnd()
                            $stdout = $process.StandardOutput.ReadToEnd()
                            $process.WaitForExit()
                            
                            # Check for errors
                            if ($process.ExitCode -ne 0) {
                                # Log error details for debugging
                                $cosignErrorFile = "$LogDir\cosign_error_$([DateTime]::Now.ToString('yyyyMMdd_HHmmss')).txt"
                                $cosignErrorOutput = @()
                                $cosignErrorOutput += "=== Cosign Error Details ==="
                                $cosignErrorOutput += "Exit Code: $($process.ExitCode)"
                                $cosignErrorOutput += "Container: $containerRef"
                                $cosignErrorOutput += "Command: $($processStartInfo.FileName) $($processStartInfo.Arguments)"
                                $cosignErrorOutput += "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
                                $cosignErrorOutput += ""
                                if ($stdout) {
                                    $cosignErrorOutput += "=== Standard Output ==="
                                    $cosignErrorOutput += $stdout
                                    $cosignErrorOutput += ""
                                }
                                if ($stderr) {
                                    $cosignErrorOutput += "=== Standard Error ==="
                                    $cosignErrorOutput += $stderr
                                    $cosignErrorOutput += ""
                                }
                                
                                $cosignErrorOutput | Out-File $cosignErrorFile -Encoding UTF8
                                
                                # Display error details to console
                                Write-Host "Cosign Error Details:" -ForegroundColor Red
                                Write-Host "Exit Code: $($process.ExitCode)" -ForegroundColor Red
                                if ($stderr) {
                                    Write-Host "Error Output:" -ForegroundColor Red
                                    Write-Host $stderr -ForegroundColor Red
                                }
                                if ($stdout) {
                                    Write-Host "Standard Output:" -ForegroundColor Yellow
                                    Write-Host $stdout -ForegroundColor Yellow
                                }
                                Write-Host "Full error details saved to: $cosignErrorFile" -ForegroundColor Yellow
                                
                                throw "Cosign container signing failed with exit code $($process.ExitCode). See error details above or check $cosignErrorFile for complete information."
                            }
                            
                            # Log successful signing
                            $successMessage = "Successfully signed container '$containerRef' using Cosign with certificate '$CertificateName'"
                            Write-Log $successMessage -Level SUCCESS -Console
                            
                            # Track signing details for reporting
                            $signingDetails = @{
                                "EventType" = "ContainerSigning"
                                "Action" = "Signed"
                                "FilePath" = $file.FullName
                                "FileName" = $file.Name
                                "ContainerRef" = $containerRef
                                "FileSize" = $file.Length
                                "FileType" = "container"
                                "CertificateName" = $CertificateName
                                "SignatureMethod" = "Cosign"
                                "KeyVaultUrl" = $config.KeyVaultUrl
                                "SignedBy" = $env:USERNAME
                                "SignedOn" = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                                "SignedOnComputer" = $env:COMPUTERNAME
                            }
                            
                            $signedFilesDetails += $signingDetails
                            $stats.Success++
                            
                            # Clean up environment variables for security
                            $env:COSIGN_AZUREKMS_RESOURCEID = $null
                            $env:COSIGN_AZUREKMS_CLIENTID = $null
                            $env:COSIGN_AZUREKMS_TENANT = $null
                        }
                        catch {
                            throw "Cosign signing failed: $_"
                        }
                    } else {
                        $stats.Skipped++
                    }
                    
                    # Skip the standard signing process for container files
                    continue
                }

                # Specific file type handling
                switch ($extension) {
                    '.zip' {
                        # ZIP files require special handling - we skip them in Test-FileSignable now
                        # but this is left here in case we add special ZIP handling in the future
                        Write-Log "ZIP files cannot be directly signed with Authenticode. Skipping." -Level WARN -Console
                        continue
                    }
                    { $_ -in @('.msix', '.appx', '.cab', '.jar') } {
                        # For container files that ARE supported, use appropriate parameters
                        Write-Log "Treating $extension file as a container format" -Level INFO -Console
                    }
                    { $_ -in @('.msi', '.msp', '.msm') } {
                        # Special handling for Windows Installer files (added .msm per Ankit)
                        $additionalParams += @("--file-digest", "sha256")
                    }
                    default {
                        # Default handling for executable/script files
                    }
                }

                # In the signing section, update arguments
                $signArgs = @(
                    "sign",
                    "--verbose"
                )
                
                # Only add continue-on-error if the parameter is set to true
                if ($ContinueOnError) {
                    $signArgs += "--continue-on-error"
                }
                
                $signArgs += @(
                    "--kvu", $config.KeyVaultUrl,
                    "--kvc", $CertificateName,
                    "--azure-key-vault-client-id", $config.ClientId,
                    "--azure-key-vault-tenant-id", $config.TenantId,
                    "--kvs", $env:AZURE_KEYVAULT_SECRET,
                    "--timestamp-rfc3161", $config.TimestampServer,
                    "--colors"
                )
                
                # Add any file-specific parameters
                $signArgs += $additionalParams
                
                if ($PSCmdlet.ShouldProcess($file.FullName, "Sign")) {
                    # Create a properly quoted command line to handle spaces in paths
                    $processStartInfo = New-Object System.Diagnostics.ProcessStartInfo
                    $processStartInfo.FileName = $azureSignToolPath
                    $processStartInfo.Arguments = "$($signArgs -join ' ') `"$($file.FullName)`""
                    $processStartInfo.RedirectStandardError = $true
                    $processStartInfo.RedirectStandardOutput = $true
                    $processStartInfo.UseShellExecute = $false
                    $processStartInfo.CreateNoWindow = $true
                    
                    # Retry logic for specific error codes
                    $maxRetries = 10
                    $retryDelay = 5  # seconds
                    $currentAttempt = 0
                    $signingSucceeded = $false
                    $lastError = $null
                    
                    while ($currentAttempt -lt $maxRetries -and -not $signingSucceeded) {
                        $currentAttempt++
                        
                        if ($currentAttempt -gt 1) {
                            Write-Log "Retry attempt $currentAttempt of $maxRetries for file: $($file.Name)" -Level WARN -Console
                            Start-Sleep -Seconds $retryDelay
                        }
                        
                        try {
                            $process = New-Object System.Diagnostics.Process
                            $process.StartInfo = $processStartInfo
                            [void]$process.Start()
                            $stderr = $process.StandardError.ReadToEnd()
                            $stdout = $process.StandardOutput.ReadToEnd()
                            $process.WaitForExit()
                            
                            if ($process.ExitCode -eq 0) {
                                $signingSucceeded = $true
                                break
                            } else {
                                # Handle both signed and unsigned representations of exit codes
                                $exitCodeUInt = if ($process.ExitCode -lt 0) {
                                    [uint32]([uint32]::MaxValue + $process.ExitCode + 1)
                                } else {
                                    [uint32]$process.ExitCode
                                }
                                
                                # Check stdout for actual Windows error codes (AzureSignTool wraps them)
                                $actualWindowsError = $null
                                if ($stdout -match "Signing failed with error ([0-9A-Fa-f]+)") {
                                    $actualWindowsError = "0x" + $matches[1]
                                }
                                
                                # Check if this is a retryable error
                                $isRetryableError = $false
                                $errorDescription = "Non-retryable signing error"
                                
                                # First check the actual Windows error code from the verbose output
                                if ($actualWindowsError) {
                                    switch ($actualWindowsError.ToUpper()) {
                                        "0x8007000B" { 
                                            $isRetryableError = $true
                                            $errorDescription = "UWP Publisher identity mismatch - retrying in case of transient issue"
                                        }
                                        "0x80070005" {
                                            $isRetryableError = $true
                                            $errorDescription = "Access denied - possible file lock"
                                        }
                                        "0x800B0001" {
                                            $isRetryableError = $true
                                            $errorDescription = "Trust provider not recognized - retrying as this can be transient"
                                        }
                                        "0x80070020" {
                                            $isRetryableError = $true
                                            $errorDescription = "File is being used by another process"
                                        }
                                        default {
                                            # Check if it's a known retryable pattern
                                            if ($actualWindowsError -match "0x9FFFB.*|0xA0000.*|0x800B0001") {
                                                $isRetryableError = $true
                                                $errorDescription = "Transient signing/authentication error"
                                            }
                                        }
                                    }
                                } else {
                                    # Fall back to checking the AzureSignTool exit code
                                    switch ($exitCodeUInt) {
                                        0xA0000002 { 
                                            # This could be Azure auth error OR wrapped UWP error
                                            # Check stdout for UWP-related messages
                                            if ($stdout -match "Publisher Identity.*does not match|AppxManifest") {
                                                $isRetryableError = $true
                                                $errorDescription = "UWP Publisher identity mismatch (wrapped) - retrying in case of transient issue"
                                            } else {
                                                $isRetryableError = $true
                                                $errorDescription = "Azure Key Vault transient authentication error"
                                            }
                                        }
                                        0x9FFFB002 { 
                                            $isRetryableError = $true
                                            $errorDescription = "Azure Key Vault access or connectivity error"
                                        }
                                        0x80070005 {
                                            $isRetryableError = $true
                                            $errorDescription = "Access denied - possible file lock"
                                        }
                                        default {
                                            $isRetryableError = $false
                                            $errorDescription = "Non-retryable signing error"
                                        }
                                    }
                                }
                                
                                $errorCodeHex = "0x{0:X8}" -f $exitCodeUInt
                                $lastError = @{
                                    ExitCode = $process.ExitCode
                                    ExitCodeHex = $errorCodeHex
                                    ActualWindowsError = $actualWindowsError
                                    Description = $errorDescription
                                    Stdout = $stdout
                                    Stderr = $stderr
                                    IsRetryable = $isRetryableError
                                }
                                
                                if ($isRetryableError -and $currentAttempt -lt $maxRetries) {
                                    Write-Log "Retryable error $errorCodeHex ($errorDescription) on attempt $currentAttempt. Will retry..." -Level WARN -Console
                                    continue
                                } else {
                                    # Either non-retryable error or max retries exceeded
                                    break
                                }
                            }
                        } catch {
                            $lastError = @{
                                ExitCode = -1
                                ExitCodeHex = "Exception"
                                Description = "Process execution failed"
                                Exception = $_.Exception.Message
                                IsRetryable = $false
                            }
                            break
                        }
                    }
                    
                    # Handle final result after retry attempts
                    if (-not $signingSucceeded) {
                        # Translate Windows error code to meaningful message
                        $exitCodeUInt = if ($lastError.ExitCode -lt 0 -and $lastError.ExitCode -ne -1) {
                            # Convert negative signed int to unsigned int
                            [uint32]([uint32]::MaxValue + $lastError.ExitCode + 1)
                        } else {
                            [uint32]$lastError.ExitCode
                        }
                        $errorCodeHex = "0x{0:X8}" -f $exitCodeUInt
                        $windowsErrorMsg = ""
                        
                        # Common Windows error codes for signing operations
                        if ($lastError.ActualWindowsError) {
                            # Use actual Windows error code for lookup
                            switch ($lastError.ActualWindowsError.ToUpper()) {
                                "0x8007000B" { $windowsErrorMsg = "UWP Publisher Identity mismatch (retried $currentAttempt times) - AppxManifest.xml Publisher does not match certificate subject" }
                                "0x80070005" { $windowsErrorMsg = "Access Denied - Insufficient permissions" }
                                "0x80070020" { $windowsErrorMsg = "File is being used by another process" }
                                "0x80092009" { $windowsErrorMsg = "Certificate not found or invalid" }
                                "0x8009200A" { $windowsErrorMsg = "Certificate has expired" }
                                "0x8009200B" { $windowsErrorMsg = "Certificate not yet valid" }
                                "0x80092010" { $windowsErrorMsg = "Certificate chain could not be built" }
                                "0x80096001" { $windowsErrorMsg = "Trust provider is not recognized or configured" }
                                "0x80096002" { $windowsErrorMsg = "Trust provider does not support the specified action" }
                                "0x80096004" { $windowsErrorMsg = "Subject is not trusted for the specified operation" }
                                "0x80096010" { $windowsErrorMsg = "Certificate signature could not be verified" }
                                "0x800B0001" { $windowsErrorMsg = "Trust provider is not recognized (retried $currentAttempt times)" }
                                "0x800B0003" { $windowsErrorMsg = "Trust provider is not known on this system" }
                                "0x800B0100" { $windowsErrorMsg = "Certificate is revoked" }
                                "0x800B0101" { $windowsErrorMsg = "Certificate or signature could not be verified" }
                                "0x800B0109" { $windowsErrorMsg = "Root certificate is not trusted" }
                                default { $windowsErrorMsg = $lastError.Description }
                            }
                        } else {
                            # Use AzureSignTool exit code for lookup
                            switch ($exitCodeUInt) {
                                0x80070005 { $windowsErrorMsg = "Access Denied - Insufficient permissions" }
                                0x80070020 { $windowsErrorMsg = "File is being used by another process" }
                                0x80092009 { $windowsErrorMsg = "Certificate not found or invalid" }
                                0x8009200A { $windowsErrorMsg = "Certificate has expired" }
                                0x8009200B { $windowsErrorMsg = "Certificate not yet valid" }
                                0x80092010 { $windowsErrorMsg = "Certificate chain could not be built" }
                                0x80096001 { $windowsErrorMsg = "Trust provider is not recognized or configured" }
                                0x80096002 { $windowsErrorMsg = "Trust provider does not support the specified action" }
                                0x80096004 { $windowsErrorMsg = "Subject is not trusted for the specified operation" }
                                0x80096010 { $windowsErrorMsg = "Certificate signature could not be verified" }
                                0x800B0001 { $windowsErrorMsg = "Trust provider is not recognized (retried $currentAttempt times)" }
                                0x800B0003 { $windowsErrorMsg = "Trust provider is not known on this system" }
                                0x800B0100 { $windowsErrorMsg = "Certificate is revoked" }
                                0x800B0101 { $windowsErrorMsg = "Certificate or signature could not be verified" }
                                0x800B0109 { $windowsErrorMsg = "Root certificate is not trusted" }
                                0x8007000B { $windowsErrorMsg = "Invalid format or data (retried $currentAttempt times) - file may contain UWP components with mismatched publisher identity" }
                                0x9FFFB002 { $windowsErrorMsg = "Azure Key Vault authentication or access error (retried $currentAttempt times)" }
                                0xA0000002 { 
                                    # Check if this is actually a UWP error wrapped by AzureSignTool
                                    if ($lastError.Stdout -match "Publisher Identity.*does not match|AppxManifest") {
                                        $windowsErrorMsg = "UWP Publisher Identity mismatch (wrapped by AzureSignTool, retried $currentAttempt times)"
                                    } else {
                                        $windowsErrorMsg = "Azure Key Vault transient authentication error - all $currentAttempt retry attempts failed"
                                    }
                                }
                                default { 
                                    # Try to get system error message or use description from retry logic
                                    if ($lastError.Description -ne "Non-retryable signing error") {
                                        $windowsErrorMsg = $lastError.Description
                                    } else {
                                        try {
                                            if ($lastError.ExitCode -ne -1) {
                                                $systemMsg = [System.ComponentModel.Win32Exception]::new($lastError.ExitCode).Message
                                                if ($systemMsg -and $systemMsg -ne "Unknown error") {
                                                    $windowsErrorMsg = $systemMsg
                                                }
                                            } else {
                                                $windowsErrorMsg = $lastError.Exception
                                            }
                                        } catch {
                                            $windowsErrorMsg = "Unknown error - check AzureSignTool documentation"
                                        }
                                    }
                                }
                            }
                        }
                        
                        # Additional diagnostic checks
                        $diagnostics = @()
                        
                        # Check file accessibility
                        try {
                            $fileInfo = Get-Item $file.FullName -ErrorAction Stop
                            if ($fileInfo.IsReadOnly) {
                                $diagnostics += "WARNING: File is marked as read-only"
                            }
                            if ($fileInfo.Length -eq 0) {
                                $diagnostics += "WARNING: File is empty (0 bytes)"
                            }
                        } catch {
                            $diagnostics += "ERROR: Cannot access file - $($_.Exception.Message)"
                        }
                        
                        # Check for file locks
                        try {
                            $fileStream = [System.IO.File]::Open($file.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
                            $fileStream.Close()
                        } catch {
                            $diagnostics += "WARNING: File may be locked by another process"
                        }
                        
                        # Check certificate expiry (if we have access to it)
                        $certDiagnostic = ""
                        try {
                            # This is a basic check - in production you'd query Key Vault directly
                            if ($CertificateName) {
                                $certDiagnostic = "Certificate: $CertificateName (check expiry in Azure Key Vault)"
                            }
                        } catch {
                            # Ignore certificate check errors
                        }
                        
                        # Log both stdout and stderr for debugging
                        $errorLogFile = "$LogDir\signing_error_$([DateTime]::Now.ToString('yyyyMMdd_HHmmss')).txt"
                        $errorOutput = @()
                        $errorOutput += "=== AzureSignTool Error Details ==="
                        $errorOutput += "AzureSignTool Exit Code: $($lastError.ExitCode) ($($lastError.ExitCodeHex))"
                        if ($lastError.ActualWindowsError) {
                            $errorOutput += "Actual Windows Error Code: $($lastError.ActualWindowsError)"
                        }
                        $errorOutput += "Error Description: $windowsErrorMsg"
                        $errorOutput += "Retry Attempts: $currentAttempt of $maxRetries"
                        if ($lastError.IsRetryable) {
                            $errorOutput += "Error Type: Retryable (exhausted all retry attempts)"
                        } else {
                            $errorOutput += "Error Type: Non-retryable"
                        }
                        $errorOutput += "File: $($file.FullName)"
                        $errorOutput += "File Size: $([math]::Round($file.Length / 1MB, 2)) MB"
                        $errorOutput += "File Extension: $($file.Extension)"
                        if ($certDiagnostic) {
                            $errorOutput += $certDiagnostic
                        }
                        $errorOutput += "Command: $($processStartInfo.FileName) $($processStartInfo.Arguments)"
                        $errorOutput += "Working Directory: $(Get-Location)"
                        $errorOutput += "User: $env:USERNAME@$env:USERDOMAIN"
                        $errorOutput += "Computer: $env:COMPUTERNAME"
                        $errorOutput += "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
                        $errorOutput += ""
                        
                        if ($diagnostics) {
                            $errorOutput += "=== Diagnostic Information ==="
                            $errorOutput += $diagnostics
                            $errorOutput += ""
                        }
                        
                        if ($lastError.Stdout) {
                            $errorOutput += "=== Standard Output ==="
                            $errorOutput += $lastError.Stdout
                            $errorOutput += ""
                        } else {
                            $errorOutput += "=== Standard Output ==="
                            $errorOutput += "(No output captured)"
                            $errorOutput += ""
                        }
                        
                        if ($lastError.Stderr) {
                            $errorOutput += "=== Standard Error ==="
                            $errorOutput += $lastError.Stderr
                            $errorOutput += ""
                        } else {
                            $errorOutput += "=== Standard Error ==="
                            $errorOutput += "(No error output captured)"
                            $errorOutput += ""
                        }
                        
                        # Add troubleshooting suggestions
                        $errorOutput += "=== Troubleshooting Suggestions ==="
                        
                        # Use actual Windows error code for troubleshooting if available
                        $troubleshootingCode = if ($lastError.ActualWindowsError) { 
                            $lastError.ActualWindowsError.ToUpper() 
                        } else { 
                            "0x{0:X8}" -f $exitCodeUInt 
                        }
                        
                        switch ($troubleshootingCode) {
                            "0x8007000B" {
                                $errorOutput += "• MSI contains UWP/APPX components with publisher identity mismatch"
                                $errorOutput += "• The Publisher in AppxManifest.xml does not match the certificate subject"
                                $errorOutput += "• This error was retried $maxRetries times before failing"
                                $errorOutput += "• Contact development team to update AppxManifest.xml Publisher identity"
                                $errorOutput += "• Publisher should match certificate CN (Common Name)"
                                $errorOutput += "• Consider signing individual UWP components separately before MSI packaging"
                                $errorOutput += "• Check certificate subject with: Get-AuthenticodeSignature or Azure Key Vault"
                            }
                            "0xA0000002" {
                                # Check if this is actually UWP wrapped in AzureSignTool error
                                if ($lastError.Stdout -match "Publisher Identity.*does not match|AppxManifest") {
                                    $errorOutput += "• UWP Publisher identity mismatch (wrapped by AzureSignTool)"
                                    $errorOutput += "• The actual error is UWP Publisher mismatch (0x8007000B)"
                                    $errorOutput += "• This error was retried $maxRetries times before failing"
                                    $errorOutput += "• Contact development team to fix AppxManifest.xml Publisher identity"
                                } else {
                                    $errorOutput += "• Transient Azure Key Vault authentication error (failed after $maxRetries retries)"
                                    $errorOutput += "• Check Azure Key Vault service status and network connectivity"
                                    $errorOutput += "• Verify service principal permissions and certificate access"
                                    $errorOutput += "• Consider increasing retry delay if network latency is high"
                                    $errorOutput += "• Try running the script again - this error is usually temporary"
                                }
                            }
                            "0x9FFFB002" {
                                $errorOutput += "• Verify Azure Key Vault permissions for the service principal"
                                $errorOutput += "• Check that the certificate name '$CertificateName' exists in Key Vault"
                                $errorOutput += "• Ensure AZURE_KEYVAULT_SECRET environment variable is set correctly"
                                $errorOutput += "• Verify network connectivity to Azure Key Vault"
                            }
                            "0x80070005" {
                                $errorOutput += "• Run as Administrator or check file/directory permissions"
                                $errorOutput += "• Ensure the signing account has access to the file"
                            }
                            "0x80070020" {
                                $errorOutput += "• Close any applications that might be using the file"
                                $errorOutput += "• Check for antivirus or backup software locking the file"
                            }
                            "0x800B0001" {
                                $errorOutput += "• Trust provider is not recognized (retried $maxRetries times)"
                                $errorOutput += "• This can be a transient Windows cryptographic service issue"
                                $errorOutput += "• Try restarting the Windows cryptographic services"
                                $errorOutput += "• Verify Windows is up to date with latest security patches"
                                $errorOutput += "• Check if antivirus is interfering with cryptographic operations"
                            }
                            "0x800B0003" {
                                $errorOutput += "• Trust provider is not known on this system (not retryable)"
                                $errorOutput += "• This is a Windows cryptographic service configuration issue"
                                $errorOutput += "• Try restarting the Windows cryptographic services: 'net stop cryptsvc && net start cryptsvc'"
                                $errorOutput += "• Verify the certificate store is accessible and not corrupted"
                                $errorOutput += "• Check system date/time - certificate validation is time-sensitive"
                                $errorOutput += "• Run 'sfc /scannow' to check for Windows system file corruption"
                                $errorOutput += "• This error typically requires system-level fixes and won't resolve with retries"
                            }
                            default {
                                $errorOutput += "• Check AzureSignTool documentation for exit code $($lastError.ExitCode)"
                                $errorOutput += "• Verify certificate is valid and not expired"
                                $errorOutput += "• Ensure proper Azure Key Vault configuration"
                                if ($lastError.ActualWindowsError) {
                                    $errorOutput += "• Look up Windows error code $($lastError.ActualWindowsError) for specific details"
                                }
                            }
                        }
                        $errorOutput += ""
                        
                        # Write to error log file
                        $errorOutput | Out-File $errorLogFile -Encoding UTF8
                        
                        # Display enhanced error details to console
                        Write-Host "AzureSignTool Error Details:" -ForegroundColor Red
                        Write-Host "AzureSignTool Exit Code: $($lastError.ExitCode) ($($lastError.ExitCodeHex))" -ForegroundColor Red
                        if ($lastError.ActualWindowsError) {
                            Write-Host "Actual Windows Error: $($lastError.ActualWindowsError)" -ForegroundColor Red
                        }
                        Write-Host "Description: $windowsErrorMsg" -ForegroundColor Red
                        Write-Host "Retry Attempts: $currentAttempt of $maxRetries" -ForegroundColor Red
                        
                        if ($lastError.IsRetryable) {
                            Write-Host "Error was retryable but all retry attempts failed" -ForegroundColor Red
                        } else {
                            Write-Host "Error was not retryable" -ForegroundColor Yellow
                        }
                        
                        if ($diagnostics) {
                            Write-Host "Diagnostics:" -ForegroundColor Yellow
                            foreach ($diag in $diagnostics) {
                                Write-Host "  $diag" -ForegroundColor Yellow
                            }
                        }
                        
                        if ($lastError.Stderr) {
                            Write-Host "Error Output:" -ForegroundColor Red
                            Write-Host $lastError.Stderr -ForegroundColor Red
                        }
                        if ($lastError.Stdout) {
                            Write-Host "Standard Output:" -ForegroundColor Yellow
                            Write-Host $lastError.Stdout -ForegroundColor Yellow
                        }
                        
                        Write-Host "Full error details saved to: $errorLogFile" -ForegroundColor Yellow
                        
                        $enhancedErrorMsg = "AzureSignTool signing failed after $currentAttempt attempts with exit code $($lastError.ExitCode) ($($lastError.ExitCodeHex)): $windowsErrorMsg"
                        throw $enhancedErrorMsg
                    }
                    
                    # Enhanced signature verification with structured SIEM logging
                    $sig = Get-AuthenticodeSignature $file.FullName
                    if ($sig.Status -eq "Valid") {
                        # Prepare complete certificate details for structured logging
                        $signingDetails = @{
                            "EventType" = "CodeSigning"
                            "Action" = "Signed"
                            "FilePath" = $file.FullName
                            "FileName" = $file.Name
                            "FileSize" = $file.Length
                            "FileType" = [System.IO.Path]::GetExtension($file.Name).TrimStart('.')
                            "CertificateName" = $CertificateName
                            "CertificateSubject" = $sig.SignerCertificate.Subject
                            "CertificateIssuer" = $sig.SignerCertificate.Issuer
                            "CertificateExpiry" = $sig.SignerCertificate.NotAfter.ToString()
                            "CertificateThumbprint" = $sig.SignerCertificate.Thumbprint
                            "SignatureStatus" = $sig.Status.ToString()
                            "KeyVaultUrl" = $config.KeyVaultUrl
                            "TimestampServer" = $config.TimestampServer
                            "SignedBy" = $env:USERNAME
                            "SignedOn" = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                            "SignedOnComputer" = $env:COMPUTERNAME
                        }
                        
                        # Add to our tracking array
                        $signedFilesDetails += $signingDetails
                        
                        # Consolidated log message that includes all the key information
                        $successMessage = "Successfully signed file '$($file.Name)' using certificate '$CertificateName' ($($sig.SignerCertificate.Thumbprint))"
                        Write-Log $successMessage -Level SUCCESS -Console
                        
                        $stats.Success++
                    } else {
                        throw "Signature verification failed: $($sig.Status). StatusMessage: $($sig.StatusMessage)"
                    }
                } else {
                    $stats.Skipped++
                }
            }
            catch {
                # Add enhanced error reporting to SIEM
                $errorDetails = @{
                    "EventType" = "CodeSigning" 
                    "Action" = "Error"
                    "FilePath" = $file.FullName
                    "FileName" = $file.Name
                    "ErrorMessage" = $_.ToString()
                    "ExceptionType" = $_.Exception.GetType().Name
                }
                
                Write-Log "Failed to sign $($file.Name)" -Level ERROR -Console
                Write-Log "Error Type: $($_.Exception.GetType().Name)" -Level ERROR -Console
                Write-Log "Error Message: $($_.Exception.Message)" -Level ERROR -Console
                
                # Display inner exception details if available
                if ($_.Exception.InnerException) {
                    Write-Log "Inner Exception: $($_.Exception.InnerException.Message)" -Level ERROR -Console
                    $errorDetails["InnerException"] = $_.Exception.InnerException.Message
                }
                
                # Display stack trace in verbose mode
                if ($VerbosePreference -eq 'Continue') {
                    Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level ERROR -Console
                }
                
                # Check for any recent error log files
                $recentErrorLogs = Get-ChildItem -Path $LogDir -Filter "signing_error_*.txt" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                if ($recentErrorLogs) {
                    Write-Log "Recent error log available: $($recentErrorLogs.FullName)" -Level ERROR -Console
                    $errorDetails["ErrorLogFile"] = $recentErrorLogs.FullName
                }
                
                $stats.Failed++
                
                # Check if we should continue on errors
                if (-not $ContinueOnError) {
                    Write-Log "ContinueOnError is disabled. Stopping execution due to signing failure." -Level ERROR -Console
                    throw "Signing failed for file '$($file.Name)' and ContinueOnError is disabled. Stopping execution."
                }
                
                continue
            }
        }
        
        # Clear the progress bar when done
        Write-Progress -Activity $activity -Completed
    }
    finally {
        if (Test-Path "$LogDir\stderr.txt") { Remove-Item "$LogDir\stderr.txt" -Force }
        $env:AZURE_KEYVAULT_SECRET = $null
        
        # Show error log summary if any errors occurred
        Show-ErrorLogSummary
    }
}

End {
    # Create a detailed file list for the summary
    $fileList = if ($stats.Success -gt 0) {
        ($signedFilesDetails | Select-Object -First 5 | ForEach-Object { $_.FileName }) -join ", "
    } else { "None" }
    
    # Add truncation indicator if more than 5 files
    if ($stats.Success -gt 5) {
        $fileList += "... (and $($stats.Success - 5) more)"
    }
    
    # Only send summary to SIEM if we actually attempted to sign files
    if ($stats.Total -gt 0) {
        # Comprehensive summary message
        $summaryMessage = "Code signing operation completed by $($env:USERNAME). " +
                         "Successfully signed $($stats.Success) of $($stats.Total) files " + 
                         "using certificate '$CertificateName'."
        
        # Determine the actual summary outcome based on success percentage
        $summaryOutcome = if ($stats.Success -eq $stats.Total) {
            "SUCCESS" # Complete success
        } elseif ($stats.Success -gt 0) {
            "WARN"   # Partial success
        } else {
            "ERROR"  # Complete failure
        }
        
        # Create a complete summary for SIEM with all details
        $siemSummary = @{
            "TotalFiles" = $stats.Total
            "SuccessfulSigns" = $stats.Success
            "FailedSigns" = $stats.Failed
            "SkippedFiles" = $stats.Skipped
            "Certificate" = $CertificateName
            "CertificateThumbprint" = if ($signedFilesDetails.Count -gt 0) { $signedFilesDetails[0].CertificateThumbprint } else { "N/A" }
            "CertificateSubject" = if ($signedFilesDetails.Count -gt 0) { $signedFilesDetails[0].CertificateSubject } else { "N/A" }
            "KeyVaultUrl" = $config.KeyVaultUrl
            "SignedFiles" = $fileList
            "SignedFilesDetails" = ($signedFilesDetails | Select-Object FileName, FilePath, FileSize, FileType, SignatureStatus, SignedBy, SignedOn)
            "Operation" = "Code signing batch operation"
            "SignedBy" = $env:USERNAME
            "SignedByDomain" = $env:USERDOMAIN
            "SignedOnComputer" = $env:COMPUTERNAME
            "CompletedAt" = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        }
        
        # Send to SIEM with complete details - and force sending regardless of EnableSIEM setting
        Send-ToSIEM -Message $summaryMessage `
                   -Level $summaryOutcome `
                   -EventType "CodeSigningSummary" `
                   -Action "Complete" `
                   -Properties $siemSummary `
                   -ForceSend
    }
    else {
        # Special case: No files were found to sign
        $noFilesMessage = "Code signing operation completed by $($env:USERNAME). No signable files found at '$Path'."
        Write-Log $noFilesMessage -Level INFO -Console
        
        # Only send a minimal info message to SIEM for no-files-found case
        Send-ToSIEM -Message $noFilesMessage `
                   -Level "INFO" `
                   -EventType "CodeSigningSummary" `
                   -Action "NoFilesFound" `
                   -Properties @{
                        "Certificate" = $CertificateName
                        "KeyVaultUrl" = $config.KeyVaultUrl
                        "SearchPath" = $Path
                        "Recurse" = $Recurse
                        "SignedBy" = $env:USERNAME
                        "SignedByDomain" = $env:USERDOMAIN
                        "SignedOnComputer" = $env:COMPUTERNAME
                        "CompletedAt" = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                   } `
                   -ForceSend
    }
    
    # Enhanced console display with border
    $border = "-" * 50
    Write-Host "`n+$border+" -ForegroundColor Cyan
    Write-Host "| Signing Operation Summary                          |" -ForegroundColor Cyan
    Write-Host "+$border+" -ForegroundColor Cyan
    Write-Host "| Certificate: $($CertificateName.PadRight(36))|" -ForegroundColor Cyan
    
    if ($stats.Total -gt 0) {
        Write-Host "| Total files processed: $($stats.Total.ToString().PadRight(26))|" -ForegroundColor Cyan
        Write-Host "| Successfully signed: $($stats.Success.ToString().PadRight(28))|" -ForegroundColor Green
        Write-Host "| Failed to sign: $($stats.Failed.ToString().PadRight(32))|" -ForegroundColor $(if ($stats.Failed -gt 0) {"Red"} else {"Gray"})
        Write-Host "| Skipped: $($stats.Skipped.ToString().PadRight(39))|" -ForegroundColor Gray
    }
    else {
        Write-Host "| No signable files found in specified path         |" -ForegroundColor Yellow
    }
    
    Write-Host "+$border+" -ForegroundColor Cyan
    Write-Host "`nTip: To update AzureSignTool or Cosign, delete the .exe file in the script directory and rerun this script." -ForegroundColor Gray
}

# SIG # Begin signature block
# MIIvjQYJKoZIhvcNAQcCoIIvfjCCL3oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDNhVN5bfgUGNrx
# ddfCxFs+9fIh7NSlBDnBEXk6t0vtX6CCFDkwggWQMIIDeKADAgECAhAFmxtXno4h
# MuI5B72nd3VcMA0GCSqGSIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNV
# BAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0xMzA4MDExMjAwMDBaFw0z
# ODAxMTUxMjAwMDBaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJ
# bmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0
# IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
# AL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3EMB/z
# G6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKyunWZ
# anMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsFxl7s
# Wxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU15zHL
# 2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJBMtfb
# BHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObURWBf3
# JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6nj3c
# AORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxBYKqx
# YxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5SUUd0
# viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+xq4aL
# T8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjQjBAMA8GA1Ud
# EwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBTs1+OC0nFdZEzf
# Lmc/57qYrhwPTzANBgkqhkiG9w0BAQwFAAOCAgEAu2HZfalsvhfEkRvDoaIAjeNk
# aA9Wz3eucPn9mkqZucl4XAwMX+TmFClWCzZJXURj4K2clhhmGyMNPXnpbWvWVPjS
# PMFDQK4dUPVS/JA7u5iZaWvHwaeoaKQn3J35J64whbn2Z006Po9ZOSJTROvIXQPK
# 7VB6fWIhCoDIc2bRoAVgX+iltKevqPdtNZx8WorWojiZ83iL9E3SIAveBO6Mm0eB
# cg3AFDLvMFkuruBx8lbkapdvklBtlo1oepqyNhR6BvIkuQkRUNcIsbiJeoQjYUIp
# 5aPNoiBB19GcZNnqJqGLFNdMGbJQQXE9P01wI4YMStyB0swylIQNCAmXHE/A7msg
# dDDS4Dk0EIUhFQEI6FUy3nFJ2SgXUE3mvk3RdazQyvtBuEOlqtPDBURPLDab4vri
# RbgjU2wGb2dVf0a1TD9uKFp5JtKkqGKX0h7i7UqLvBv9R0oN32dmfrJbQdA75PQ7
# 9ARj6e/CVABRoIoqyc54zNXqhwQYs86vSYiv85KZtrPmYQ/ShQDnUBrkG5WdGaG5
# nLGbsQAe79APT0JsyQq87kP6OnGlyE0mpTX9iV28hWIdMtKgK1TtmlfB2/oQzxm3
# i0objwG2J5VT6LaJbVu8aNQj6ItRolb58KaAoNYes7wPD1N1KarqE3fk3oyBIa0H
# EEcRrYc9B9F1vM/zZn4wggawMIIEmKADAgECAhAIrUCyYNKcTJ9ezam9k67ZMA0G
# CSqGSIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJ
# bmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0
# IFRydXN0ZWQgUm9vdCBHNDAeFw0yMTA0MjkwMDAwMDBaFw0zNjA0MjgyMzU5NTla
# MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UE
# AxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5NiBTSEEz
# ODQgMjAyMSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDVtC9C
# 0CiteLdd1TlZG7GIQvUzjOs9gZdwxbvEhSYwn6SOaNhc9es0JAfhS0/TeEP0F9ce
# 2vnS1WcaUk8OoVf8iJnBkcyBAz5NcCRks43iCH00fUyAVxJrQ5qZ8sU7H/Lvy0da
# E6ZMswEgJfMQ04uy+wjwiuCdCcBlp/qYgEk1hz1RGeiQIXhFLqGfLOEYwhrMxe6T
# SXBCMo/7xuoc82VokaJNTIIRSFJo3hC9FFdd6BgTZcV/sk+FLEikVoQ11vkunKoA
# FdE3/hoGlMJ8yOobMubKwvSnowMOdKWvObarYBLj6Na59zHh3K3kGKDYwSNHR7Oh
# D26jq22YBoMbt2pnLdK9RBqSEIGPsDsJ18ebMlrC/2pgVItJwZPt4bRc4G/rJvmM
# 1bL5OBDm6s6R9b7T+2+TYTRcvJNFKIM2KmYoX7BzzosmJQayg9Rc9hUZTO1i4F4z
# 8ujo7AqnsAMrkbI2eb73rQgedaZlzLvjSFDzd5Ea/ttQokbIYViY9XwCFjyDKK05
# huzUtw1T0PhH5nUwjewwk3YUpltLXXRhTT8SkXbev1jLchApQfDVxW0mdmgRQRNY
# mtwmKwH0iU1Z23jPgUo+QEdfyYFQc4UQIyFZYIpkVMHMIRroOBl8ZhzNeDhFMJlP
# /2NPTLuqDQhTQXxYPUez+rbsjDIJAsxsPAxWEQIDAQABo4IBWTCCAVUwEgYDVR0T
# AQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUaDfg67Y7+F8Rhvv+YXsIiGX0TkIwHwYD
# VR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMG
# A1UdJQQMMAoGCCsGAQUFBwMDMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYY
# aHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2Fj
# ZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNV
# HR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkUm9vdEc0LmNybDAcBgNVHSAEFTATMAcGBWeBDAEDMAgGBmeBDAEEATAN
# BgkqhkiG9w0BAQwFAAOCAgEAOiNEPY0Idu6PvDqZ01bgAhql+Eg08yy25nRm95Ry
# sQDKr2wwJxMSnpBEn0v9nqN8JtU3vDpdSG2V1T9J9Ce7FoFFUP2cvbaF4HZ+N3HL
# IvdaqpDP9ZNq4+sg0dVQeYiaiorBtr2hSBh+3NiAGhEZGM1hmYFW9snjdufE5Btf
# Q/g+lP92OT2e1JnPSt0o618moZVYSNUa/tcnP/2Q0XaG3RywYFzzDaju4ImhvTnh
# OE7abrs2nfvlIVNaw8rpavGiPttDuDPITzgUkpn13c5UbdldAhQfQDN8A+KVssIh
# dXNSy0bYxDQcoqVLjc1vdjcshT8azibpGL6QB7BDf5WIIIJw8MzK7/0pNVwfiThV
# 9zeKiwmhywvpMRr/LhlcOXHhvpynCgbWJme3kuZOX956rEnPLqR0kq3bPKSchh/j
# wVYbKyP/j7XqiHtwa+aguv06P0WmxOgWkVKLQcBIhEuWTatEQOON8BUozu3xGFYH
# Ki8QxAwIZDwzj64ojDzLj4gLDb879M4ee47vtevLt/B3E+bnKD+sEq6lLyJsQfmC
# XBVmzGwOysWGw/YmMwwHS6DTBwJqakAwSEs0qFEgu60bhQjiWQ1tygVQK+pKHJ6l
# /aCnHwZ05/LWUpD9r4VIIflXO7ScA+2GRfS0YW6/aOImYIbqyK+p/pQd52MbOoZW
# eE4wggftMIIF1aADAgECAhABg0HAZ+Xwq/zP2GToyihnMA0GCSqGSIb3DQEBCwUA
# MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UE
# AxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5NiBTSEEz
# ODQgMjAyMSBDQTEwHhcNMjUwMTIzMDAwMDAwWhcNMjgwMTI1MjM1OTU5WjCB9TET
# MBEGCysGAQQBgjc8AgEDEwJVUzEZMBcGCysGAQQBgjc8AgECEwhEZWxhd2FyZTEd
# MBsGA1UEDwwUUHJpdmF0ZSBPcmdhbml6YXRpb24xEDAOBgNVBAUTBzMwODMwNTQx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1UaG91
# c2FuZCBPYWtzMSswKQYDVQQKEyJUZWxlZHluZSBUZWNobm9sb2dpZXMgSW5jb3Jw
# b3JhdGVkMSswKQYDVQQDEyJUZWxlZHluZSBUZWNobm9sb2dpZXMgSW5jb3Jwb3Jh
# dGVkMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAjKpnX528gwhrmne0
# Z2lXDsWht9HiWWYzGkMP8iDix0Mge2ZgBiWw8NgA/DHmj1tCzgFbB8Kc9/Lh4w5R
# lNPs0M2g+QyE7DJtaTMsOj8mIP6ThdxoDfohyyB17hPLlDX1sYcw/w3nuuRAE3Qk
# yqhRiReU6E37ew8ktxOPEa0y2me3EMEiWz16I6T+dlGYPzBZUUCQ9rfFS1zVpcPe
# eFaGFGSh2WMh9bYbsG/xUni81/r5MJb4U+PJrzQWWnclXaIMXMsoCJsvPEkuGJDj
# 72SYJ7zcezsSyieD7uLIr+Ctm9bNWejYBZie/2yY7cO5oW4FcWYlkTIR9mpPn6tf
# WkpMdSyEaqCgRw2xk1SxA5qr/MBjXQBaugkq16PgtnkQfZJHtBoNhEZ++8ehPOUf
# 9fBVyGK84OUy0q7fAuyt6pHlBqe7UPKzR51dDr9wrDEZqAe8vXVjWjX+fHVUM/xv
# 9cVXC02ft1cevLlxu8HOirARnsHtsmlIuVMRthOmAZ14WXZOV+sIU9kiBl0RZuzP
# gy/M3Arn10nS9rcVMIvgoPt9qsGIoR/9OQT/WlC4KuVX2ta12WEcz7bMG9etwm4s
# 6erUhMfkmfYZ6fgzgcydzBcLHRu2ZWCEfA8zJ/jVagGThjPsyUjaY4fXckFocKcK
# xabPQBxRYTAEVjD5lq/Wh6Nu0TsCAwEAAaOCAgIwggH+MB8GA1UdIwQYMBaAFGg3
# 4Ou2O/hfEYb7/mF7CIhl9E5CMB0GA1UdDgQWBBT97y3EZzfmedAajrEbfWpGub+F
# bzA9BgNVHSAENjA0MDIGBWeBDAEDMCkwJwYIKwYBBQUHAgEWG2h0dHA6Ly93d3cu
# ZGlnaWNlcnQuY29tL0NQUzAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYB
# BQUHAwMwgbUGA1UdHwSBrTCBqjBToFGgT4ZNaHR0cDovL2NybDMuZGlnaWNlcnQu
# Y29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNpZ25pbmdSU0E0MDk2U0hBMzg0MjAy
# MUNBMS5jcmwwU6BRoE+GTWh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2Vy
# dFRydXN0ZWRHNENvZGVTaWduaW5nUlNBNDA5NlNIQTM4NDIwMjFDQTEuY3JsMIGU
# BggrBgEFBQcBAQSBhzCBhDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNl
# cnQuY29tMFwGCCsGAQUFBzAChlBodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20v
# RGlnaUNlcnRUcnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZTSEEzODQyMDIxQ0Ex
# LmNydDAJBgNVHRMEAjAAMA0GCSqGSIb3DQEBCwUAA4ICAQAKDwZT38qesrKUO8mC
# PFihP4sW90EAJj3ECQRP4JV3e2KizMeZGA8c9wn5aUjNyrq11U0NXe7MrPeGP5v4
# xZhHMQC2iIq1ZI6z6D4bgBOo8q8mX4L/e3XYqCpgyXQq6a6kdZhnA0i6GtKNfrVO
# WeAar4nObk/2lTJtLfw1q/KHzYUYtJSUFPl031tyUAg969xbhUiX09CI+l3E7C7y
# zeZcQ2aqSy3qdYAz1BQCr3sK50AohAlTNOZD2TDJDA3vdsbIPSWpFT8SPeLQMMD+
# jJPKiTiFs/anjUvZFbURcdT517/BBupC7FjzQRBWS4A3AiodRv1cBeEy0j7rdFMU
# fqk1ONh+tdxrxPCj+e1e7tjgpyppOVyYfGMsvxqXR7quTZnni//fOzI7vRxlzrBS
# epsHelnSVRae62IFvCz9eh5qzksL72EZVHvBSb6f3ZPQ/N7t8UmfBs5vnQ4O/o8E
# 7T81BllWuNSh6pv5M37VN5BQaRRRyRYgG4bEn2Q0l6tnRlr+4FNluv/lijFA2gUZ
# Yw2P+owlX/Q5TIgL9HAfN0LlQy4ZKsBmD42bslA8lBe0363fFc/5FKRpB7YiUGC4
# qQ5Au65g67V/ElU8ks3xzE1evYVFvckWXWot6tNX9b5FFfW2FqhSAD3hwsz5VjcO
# lGSgOYajIVk1aK52IJz8WgCXrDGCGqowghqmAgEBMH0waTELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVz
# dGVkIEc0IENvZGUgU2lnbmluZyBSU0E0MDk2IFNIQTM4NCAyMDIxIENBMQIQAYNB
# wGfl8Kv8z9hk6MooZzANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3AgEMMQow
# CKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcC
# AQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAVFHGQHtv/QwUx21Hv
# bFvdSBpk8XJtd+hcjVKoBiUfRTANBgkqhkiG9w0BAQEFAASCAgAFNS3VlVHG+3GF
# EVuv0RWgB9hzQdqwrdn+bZXGVSynsuv9zma1lSctzBp4J7mRvlCq7iqBP87W6kCW
# hmJaXBvPCfncJBwsgqENA6qqMRDKazCFt8ASYEt1Snc+uDmECZ0+cuCabG+G4+pp
# 8gEGZILqZDXJpDBL0EgwYhQ7LOyNf/dh5Ia7s1MMpZLYqB49xC734AnA/RnVdYOi
# E115mPF9sU5Nd5kL8jpviQseM5yXVkA38ZODmtP+NVwk63mTDH5/mh9zAbNlO6VJ
# JNOD3fKdbewjdmDVw4swztCEGeNSb/FTCRmNV8uf5krCypiwPGyLC+ah4giPHQ0G
# xB3ue89oHXWyJHxR4pFPn/837BaPa+lVmLidBfo2YJA155Jkt1IEdqfSFOuq/T+j
# WWAOldpxtNqdySCviLpgqzjhl2Q1UkPgi255AcUSKbXfgTCkw7er+q5uw/M2Tqba
# iIMsdk4D6RI1mUo3lT8MrcyavDHDo/GLEXYyh1rZhtll0GdlKTw+0PjKYzPt97P3
# pD4YUIXNzQj9rciwqc2miiiakfhau2P0Z7fpb+8daigncjnBoUql2VbHbhXpXf31
# qlWcNbUS4fCe41e7y5rplkjAslChr8j79ZQIqXmxRYgpc30yvISOY9gRhMyeJxbd
# RFV6uvVW4M5zni8OKA1ljfwZniS0dKGCF3cwghdzBgorBgEEAYI3AwMBMYIXYzCC
# F18GCSqGSIb3DQEHAqCCF1AwghdMAgEDMQ8wDQYJYIZIAWUDBAIBBQAweAYLKoZI
# hvcNAQkQAQSgaQRnMGUCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFlAwQCAQUABCCB
# Ss2dgi+5a1xn7PBhkZ5FCy5L+ia8ewCzm/P2Dtnq0AIRANmxprfRKQ7U1u1GSunq
# tBkYDzIwMjUwNzEwMTcyMzA0WqCCEzowggbtMIIE1aADAgECAhAKgO8YS43xBYLR
# xHanlXRoMA0GCSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5E
# aWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1l
# U3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwHhcNMjUwNjA0MDAwMDAw
# WhcNMzYwOTAzMjM1OTU5WjBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNl
# cnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFNIQTI1NiBSU0E0MDk2IFRpbWVz
# dGFtcCBSZXNwb25kZXIgMjAyNSAxMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEA0EasLRLGntDqrmBWsytXum9R/4ZwCgHfyjfMGUIwYzKomd8U1nH7C8Dr
# 0cVMF3BsfAFI54um8+dnxk36+jx0Tb+k+87H9WPxNyFPJIDZHhAqlUPt281mHrBb
# ZHqRK71Em3/hCGC5KyyneqiZ7syvFXJ9A72wzHpkBaMUNg7MOLxI6E9RaUueHTQK
# WXymOtRwJXcrcTTPPT2V1D/+cFllESviH8YjoPFvZSjKs3SKO1QNUdFd2adw44wD
# cKgH+JRJE5Qg0NP3yiSyi5MxgU6cehGHr7zou1znOM8odbkqoK+lJ25LCHBSai25
# CFyD23DZgPfDrJJJK77epTwMP6eKA0kWa3osAe8fcpK40uhktzUd/Yk0xUvhDU6l
# vJukx7jphx40DQt82yepyekl4i0r8OEps/FNO4ahfvAk12hE5FVs9HVVWcO5J4dV
# mVzix4A77p3awLbr89A90/nWGjXMGn7FQhmSlIUDy9Z2hSgctaepZTd0ILIUbWuh
# KuAeNIeWrzHKYueMJtItnj2Q+aTyLLKLM0MheP/9w6CtjuuVHJOVoIJ/DtpJRE7C
# e7vMRHoRon4CWIvuiNN1Lk9Y+xZ66lazs2kKFSTnnkrT3pXWETTJkhd76CIDBbTR
# ofOsNyEhzZtCGmnQigpFHti58CSmvEyJcAlDVcKacJ+A9/z7eacCAwEAAaOCAZUw
# ggGRMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFOQ7/PIx7f391/ORcWMZUEPPYYzo
# MB8GA1UdIwQYMBaAFO9vU0rp5AZ8esrikFb2L9RJ7MtOMA4GA1UdDwEB/wQEAwIH
# gDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDCBlQYIKwYBBQUHAQEEgYgwgYUwJAYI
# KwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBdBggrBgEFBQcwAoZR
# aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0VGlt
# ZVN0YW1waW5nUlNBNDA5NlNIQTI1NjIwMjVDQTEuY3J0MF8GA1UdHwRYMFYwVKBS
# oFCGTmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRp
# bWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNybDAgBgNVHSAEGTAXMAgG
# BmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBAGUqrfEcJwS5
# rmBB7NEIRJ5jQHIh+OT2Ik/bNYulCrVvhREafBYF0RkP2AGr181o2YWPoSHz9iZE
# N/FPsLSTwVQWo2H62yGBvg7ouCODwrx6ULj6hYKqdT8wv2UV+Kbz/3ImZlJ7YXwB
# D9R0oU62PtgxOao872bOySCILdBghQ/ZLcdC8cbUUO75ZSpbh1oipOhcUT8lD8QA
# GB9lctZTTOJM3pHfKBAEcxQFoHlt2s9sXoxFizTeHihsQyfFg5fxUFEp7W42fNBV
# N4ueLaceRf9Cq9ec1v5iQMWTFQa0xNqItH3CPFTG7aEQJmmrJTV3Qhtfparz+BW6
# 0OiMEgV5GWoBy4RVPRwqxv7Mk0Sy4QHs7v9y69NBqycz0BZwhB9WOfOu/CIJnzkQ
# TwtSSpGGhLdjnQ4eBpjtP+XB3pQCtv4E5UCSDag6+iX8MmB10nfldPF9SVD7weCC
# 3yXZi/uuhqdwkgVxuiMFzGVFwYbQsiGnoa9F5AaAyBjFBtXVLcKtapnMG3VH3EmA
# p/jsJ3FVF3+d1SVDTmjFjLbNFZUWMXuZyvgLfgyPehwJVxwC+UpX2MSey2ueIu9T
# HFVkT+um1vshETaWyQo8gmBto/m3acaP9QsuLj3FNwFlTxq25+T4QwX9xa6ILs84
# ZPvmpovq90K8eWyG2N01c4IhSOxqt81nMIIGtDCCBJygAwIBAgIQDcesVwX/IZku
# QEMiDDpJhjANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMM
# RGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQD
# ExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwHhcNMjUwNTA3MDAwMDAwWhcNMzgw
# MTE0MjM1OTU5WjBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIElu
# Yy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJT
# QTQwOTYgU0hBMjU2IDIwMjUgQ0ExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAtHgx0wqYQXK+PEbAHKx126NGaHS0URedTa2NDZS1mZaDLFTtQ2oRjzUX
# MmxCqvkbsDpz4aH+qbxeLho8I6jY3xL1IusLopuW2qftJYJaDNs1+JH7Z+QdSKWM
# 06qchUP+AbdJgMQB3h2DZ0Mal5kYp77jYMVQXSZH++0trj6Ao+xh/AS7sQRuQL37
# QXbDhAktVJMQbzIBHYJBYgzWIjk8eDrYhXDEpKk7RdoX0M980EpLtlrNyHw0Xm+n
# t5pnYJU3Gmq6bNMI1I7Gb5IBZK4ivbVCiZv7PNBYqHEpNVWC2ZQ8BbfnFRQVESYO
# szFI2Wv82wnJRfN20VRS3hpLgIR4hjzL0hpoYGk81coWJ+KdPvMvaB0WkE/2qHxJ
# 0ucS638ZxqU14lDnki7CcoKCz6eum5A19WZQHkqUJfdkDjHkccpL6uoG8pbF0LJA
# QQZxst7VvwDDjAmSFTUms+wV/FbWBqi7fTJnjq3hj0XbQcd8hjj/q8d6ylgxCZSK
# i17yVp2NL+cnT6Toy+rN+nM8M7LnLqCrO2JP3oW//1sfuZDKiDEb1AQ8es9Xr/u6
# bDTnYCTKIsDq1BtmXUqEG1NqzJKS4kOmxkYp2WyODi7vQTCBZtVFJfVZ3j7OgWmn
# hFr4yUozZtqgPrHRVHhGNKlYzyjlroPxul+bgIspzOwbtmsgY1MCAwEAAaOCAV0w
# ggFZMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFO9vU0rp5AZ8esrikFb2
# L9RJ7MtOMB8GA1UdIwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB
# /wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcBAQRrMGkwJAYI
# KwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1
# aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RH
# NC5jcnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGlnaWNlcnQuY29t
# L0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIw
# CwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQAXzvsWgBz+Bz0RdnEwvb4L
# yLU0pn/N0IfFiBowf0/Dm1wGc/Do7oVMY2mhXZXjDNJQa8j00DNqhCT3t+s8G0iP
# 5kvN2n7Jd2E4/iEIUBO41P5F448rSYJ59Ib61eoalhnd6ywFLerycvZTAz40y8S4
# F3/a+Z1jEMK/DMm/axFSgoR8n6c3nuZB9BfBwAQYK9FHaoq2e26MHvVY9gCDA/JY
# sq7pGdogP8HRtrYfctSLANEBfHU16r3J05qX3kId+ZOczgj5kjatVB+NdADVZKON
# /gnZruMvNYY2o1f4MXRJDMdTSlOLh0HCn2cQLwQCqjFbqrXuvTPSegOOzr4EWj7P
# tspIHBldNE2K9i697cvaiIo2p61Ed2p8xMJb82Yosn0z4y25xUbI7GIN/TpVfHIq
# Q6Ku/qjTY6hc3hsXMrS+U0yy+GWqAXam4ToWd2UQ1KYT70kZjE4YtL8Pbzg0c1ug
# MZyZZd/BdHLiRu7hAWE6bTEm4XYRkA6Tl4KSFLFk43esaUeqGkH/wyW4N7Oigizw
# JWeukcyIPbAvjSabnf7+Pu0VrFgoiovRDiyx3zEdmcif/sYQsfch28bZeUz2rtY/
# 9TCA6TD8dC3JE3rYkrhLULy7Dc90G6e8BlqmyIjlgp2+VqsS9/wQD7yFylIz0scm
# bKvFoW2jNrbM1pD2T7m3XDCCBY0wggR1oAMCAQICEA6bGI750C3n79tQ4ghAGFow
# DQYJKoZIhvcNAQEMBQAwZTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0
# IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEkMCIGA1UEAxMbRGlnaUNl
# cnQgQXNzdXJlZCBJRCBSb290IENBMB4XDTIyMDgwMTAwMDAwMFoXDTMxMTEwOTIz
# NTk1OVowYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcG
# A1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3Rl
# ZCBSb290IEc0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAv+aQc2je
# u+RdSjwwIjBpM+zCpyUuySE98orYWcLhKac9WKt2ms2uexuEDcQwH/MbpDgW61bG
# l20dq7J58soR0uRf1gU8Ug9SH8aeFaV+vp+pVxZZVXKvaJNwwrK6dZlqczKU0RBE
# EC7fgvMHhOZ0O21x4i0MG+4g1ckgHWMpLc7sXk7Ik/ghYZs06wXGXuxbGrzryc/N
# rDRAX7F6Zu53yEioZldXn1RYjgwrt0+nMNlW7sp7XeOtyU9e5TXnMcvak17cjo+A
# 2raRmECQecN4x7axxLVqGDgDEI3Y1DekLgV9iPWCPhCRcKtVgkEy19sEcypukQF8
# IUzUvK4bA3VdeGbZOjFEmjNAvwjXWkmkwuapoGfdpCe8oU85tRFYF/ckXEaPZPfB
# aYh2mHY9WV1CdoeJl2l6SPDgohIbZpp0yt5LHucOY67m1O+SkjqePdwA5EUlibaa
# RBkrfsCUtNJhbesz2cXfSwQAzH0clcOP9yGyshG3u3/y1YxwLEFgqrFjGESVGnZi
# fvaAsPvoZKYz0YkH4b235kOkGLimdwHhD5QMIR2yVCkliWzlDlJRR3S+Jqy2QXXe
# eqxfjT/JvNNBERJb5RBQ6zHFynIWIgnffEx1P2PsIV/EIFFrb7GrhotPwtZFX50g
# /KEexcCPorF+CiaZ9eRpL5gdLfXZqbId5RsCAwEAAaOCATowggE2MA8GA1UdEwEB
# /wQFMAMBAf8wHQYDVR0OBBYEFOzX44LScV1kTN8uZz/nupiuHA9PMB8GA1UdIwQY
# MBaAFEXroq/0ksuCMS1Ri6enIZ3zbcgPMA4GA1UdDwEB/wQEAwIBhjB5BggrBgEF
# BQcBAQRtMGswJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBD
# BggrBgEFBQcwAoY3aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0
# QXNzdXJlZElEUm9vdENBLmNydDBFBgNVHR8EPjA8MDqgOKA2hjRodHRwOi8vY3Js
# My5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMBEGA1Ud
# IAQKMAgwBgYEVR0gADANBgkqhkiG9w0BAQwFAAOCAQEAcKC/Q1xV5zhfoKN0Gz22
# Ftf3v1cHvZqsoYcs7IVeqRq7IviHGmlUIu2kiHdtvRoU9BNKei8ttzjv9P+Aufih
# 9/Jy3iS8UgPITtAq3votVs/59PesMHqai7Je1M/RQ0SbQyHrlnKhSLSZy51PpwYD
# E3cnRNTnf+hZqPC/Lwum6fI0POz3A8eHqNJMQBk1RmppVLC4oVaO7KTVPeix3P0c
# 2PR3WlxUjG/voVA9/HYJaISfb8rbII01YBwCA8sgsKxYoA5AY8WYIsGyWfVVa88n
# q2x2zm8jLfR+cWojayL/ErhULSd+2DrZ8LaHlv1b0VysGMNNn3O3AamfV6peKOK5
# lDGCA3wwggN4AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0
# LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGlu
# ZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglg
# hkgBZQMEAgEFAKCB0TAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwHAYJKoZI
# hvcNAQkFMQ8XDTI1MDcxMDE3MjMwNFowKwYLKoZIhvcNAQkQAgwxHDAaMBgwFgQU
# 3WIwrIYKLTBr2jixaHlSMAf7QX4wLwYJKoZIhvcNAQkEMSIEIKvdr4Xrj+9v48U7
# H25jqmSBw0McvZANHdNpqfby9e8sMDcGCyqGSIb3DQEJEAIvMSgwJjAkMCIEIEqg
# P6Is11yExVyTj4KOZ2ucrsqzP+NtJpqjNPFGEQozMA0GCSqGSIb3DQEBAQUABIIC
# AFOxOviO1dNy3kg0/jTIqlr829SRxjCadSGXqvUu3yN2KIsIYPDxbNDl3ZcFPjJ8
# LdrYn20WecnGAhbu7DF7436zeZsB5SxGmUYy3Skgb7VWh7i58/5U6cFZRIHrekfb
# GO68zw222W2NqzOKa7zpYBDzaw10gvWFRr4IMj1N7KBtsMTsfW2LrggYtNqZecpV
# DQvybtc9TvLtls1qS92AAuYNeNyi9f+cNucAEnMX37/CD2E8x5mPvexd0Xq7BSO5
# R/5c85Sua5VS6BX/l2MHq7ubxJ414w1sUpk2HzpfhgcxEVctYi3o6biXRN18Jq/9
# lYbqAvZd5yCQMszEEOkNCkVEy7bdeow/EH7iAZFufkGHwMPKbElhti9/ViTKl4Uv
# JtgSEUBc884W9MElK4IZCuJC/3c2WY1/DHSVWLwX1D8TV62Ry8dN9BP5kL7dwDiR
# To2x+PHv5ad4E902iZkJPEQSE60euNsoFs74hWPoZvJ13bRs7vQB6glsOew8E1oE
# iKGZ/89nZVctKODiARMhT1sLrfdzYajQcdks5pmgep//gSDOaiUuHtzKMslcYBHE
# 9/pxqPxsqTApC3So4oHIWwEUbIDWrJdlKBGr+9FD9X1evEGpfaxCqoAupMrOSPNw
# F3oQeJcoTh9pDd06njBiS302vdi6BMxrxcjVaSIZlkNH
# SIG # End signature block
