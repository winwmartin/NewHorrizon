<#
.SYNOPSIS
    Diagnoses and remediates the ~63-second Omnissa Horizon Client startup stall caused by
    the client's connections to the machine's OWN address being silently dropped.

.DESCRIPTION
    Evidence (Procmon capture of horizon-client.exe, 2026-10-06 11:22:13 - 11:23:49):
      * The client opens three local TCP connections to the machine's own FQDN address
        (ephemeral ports ~58397 / 58417 / 58440). The SYN is never answered: Procmon shows
        TCP Reconnect (SYN retransmit) at +1s, +3s, +7s, +15s and a TCP Disconnect at +21s.
      * No TCP Accept is logged for those ports, so the packet never reached a listener.
      * Immediately after each 21s failure the client reconnects over 'view-localhost' and
        succeeds in under 1 ms. Three failures x 21s = 63s of the ~73s time-to-UI.
      * Profile-file writes (0.66s), registry (0.29s) and runtime load (~10s) are NOT the cause.
      * SentinelOne (InProcessClient64.dll, IdrApiMon64.dll) and Symantec DLP (prntm64.dll) are
        injected into the process at start; Eracent loads only AFTER the last stall.

    A silent drop (no RST) means a filter on the path discarded the packet. Candidates, in
    order of estimated likelihood: Windows Defender Firewall inbound rule/default action,
    SentinelOne network/firewall control, Symantec DLP network filter, another WFP callout.
    This script identifies which one, and applies the one fix that can be done safely from the
    endpoint (a tightly scoped Windows Firewall allow rule). Fixes for SentinelOne / DLP must be
    made in those products' consoles - use -ExportSecurityRequest to generate the ticket text.

.PARAMETER Diagnose
    Read-only. Identifies the client binary (signature, hash, version), runs a self-address TCP
    probe (loopback vs own FQDN vs own IPs), reports Windows Firewall state and rules for the
    client, lists installed security services, and counts third-party WFP filters.

.PARAMETER MeasureLaunch
    Launches the client, measures seconds until its main window appears, then closes it.
    Run before and after a fix to prove the improvement.

.PARAMETER CaptureWfp
    Starts a Windows Filtering Platform capture, launches the client, waits -CaptureSeconds,
    stops the capture and tries to name the filter that dropped the client's traffic.
    Keep wfpdiag-*.cab: your security team can open it if the automatic summary is empty.

.PARAMETER FixFirewallRule
    Creates an inbound Allow rule for the client program, limited to this machine's own
    addresses (-FirewallScope Self, default) or the local subnet (-FirewallScope LocalSubnet).
    In Self mode a scheduled task refreshes the addresses on network changes. If Windows
    Firewall ignores local rules (GPO merge disabled) the script writes a GPO-ready definition.

.PARAMETER ExportSecurityRequest
    Writes a ready-to-send exclusion/allow request (path, SHA256, signer, observed flows) for the
    SentinelOne, Symantec DLP and firewall owners.

.PARAMETER All
    Diagnose + ExportSecurityRequest + FixFirewallRule. (MeasureLaunch/CaptureWfp are opt-in
    because they launch the client.)

.EXAMPLE
    .\Resolve-HorizonClientLoopbackStall.ps1 -Diagnose -MeasureLaunch

.EXAMPLE
    .\Resolve-HorizonClientLoopbackStall.ps1 -CaptureWfp

.EXAMPLE
    .\Resolve-HorizonClientLoopbackStall.ps1 -FixFirewallRule -MeasureLaunch -WhatIf

.NOTES
    Run elevated on the affected endpoint. Pilot first. Every state-changing action honors -WhatIf.
    Nothing here disables security software or changes TCP timeouts system-wide.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Diagnose,
    [switch]$MeasureLaunch,
    [switch]$CaptureWfp,
    [switch]$FixFirewallRule,
    [switch]$ExportSecurityRequest,
    [switch]$All,
    [ValidateSet('Self', 'LocalSubnet')][string]$FirewallScope = 'Self',
    [string]$ClientPath,
    [int]$ProbeTimeoutSeconds = 25,
    [int]$CaptureSeconds = 90,
    [string]$OutDir = "$env:ProgramData\HorizonStartupFix"
)

$ErrorActionPreference = 'Continue'
$script:Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$script:Results = [System.Collections.Generic.List[pscustomobject]]::new()
$script:SecurityPattern = 'Sentinel|Symantec|Vontu|EDPA|Eracent|CrowdStrike|Tanium|Zscaler|Netskope|Forcepoint|McAfee|Trellix|Cisco|AnyConnect|GlobalProtect|Defender'

if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
$script:LogPath = Join-Path $OutDir 'loopback-stall.log'

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = '[{0}] [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Add-Content -Path $script:LogPath -Value $line
    Write-Host $line
}

function Add-Result {
    param([string]$Step, [string]$Status, [string]$Detail)
    $script:Results.Add([pscustomobject]@{ Step = $Step; Status = $Status; Detail = $Detail })
}

function Test-IsAdministrator {
    $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-HorizonClientPath {
    if ($ClientPath -and (Test-Path $ClientPath)) { return (Resolve-Path $ClientPath).Path }
    $candidates = @(
        "$env:ProgramFiles\Omnissa\Omnissa Horizon Client\horizon-client.exe",
        "${env:ProgramFiles(x86)}\Omnissa\Omnissa Horizon Client\horizon-client.exe",
        "$env:ProgramFiles\VMware\VMware Horizon View Client\vmware-view.exe",
        "${env:ProgramFiles(x86)}\VMware\VMware Horizon View Client\vmware-view.exe"
    )
    return ($candidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1)
}

function Get-ClientIdentity {
    param([string]$Path)
    $sig = Get-AuthenticodeSignature -FilePath $Path
    [pscustomobject]@{
        Path      = $Path
        Version   = (Get-Item $Path).VersionInfo.FileVersion
        Signature = $sig.Status
        Signer    = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '(unsigned)' }
        SHA256    = (Get-FileHash -Path $Path -Algorithm SHA256).Hash
    }
}

function Get-OwnIPv4Addresses {
    [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() |
        Where-Object { $_.OperationalStatus -eq 'Up' -and $_.NetworkInterfaceType -ne 'Loopback' } |
        ForEach-Object { $_.GetIPProperties().UnicastAddresses } |
        Where-Object { $_.Address.AddressFamily -eq 'InterNetwork' -and $_.Address.ToString() -notlike '169.254.*' } |
        ForEach-Object { $_.Address.ToString() } | Select-Object -Unique
}

function Test-SelfConnect {
    # Replicates the failing pattern without the client: listen on Any:<ephemeral>, then connect to
    # 127.0.0.1, the machine's FQDN address(es) and each local IPv4. A TIMEOUT (not "refused") means a
    # machine-wide filter silently drops the traffic. Instant success here but a stall in the client
    # points at a per-program rule for horizon-client.exe instead.
    param([int]$TimeoutSeconds)
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, 0)
    $listener.Start()
    $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
    $targets = [System.Collections.Generic.List[object]]::new()
    $targets.Add([pscustomobject]@{ Label = 'Loopback'; Address = '127.0.0.1' })
    try {
        $fqdn = [System.Net.Dns]::GetHostEntry([System.Net.Dns]::GetHostName()).HostName
        foreach ($a in [System.Net.Dns]::GetHostAddresses($fqdn) | Where-Object { $_.AddressFamily -eq 'InterNetwork' }) {
            $targets.Add([pscustomobject]@{ Label = "FQDN $fqdn"; Address = $a.ToString() })
        }
    } catch { Write-Log "FQDN resolution failed: $($_.Exception.Message)" 'WARN' }
    foreach ($ip in Get-OwnIPv4Addresses) {
        $targets.Add([pscustomobject]@{ Label = 'Local interface IP'; Address = $ip })
    }
    try {
        foreach ($t in $targets) {
            $client = [System.Net.Sockets.TcpClient]::new()
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $outcome = ''
            try {
                $task = $client.ConnectAsync($t.Address, $port)
                if ($task.Wait([TimeSpan]::FromSeconds($TimeoutSeconds))) { $outcome = 'Connected' }
                else { $outcome = 'TIMEOUT - packet silently dropped' }
            } catch { $outcome = 'Refused/error: ' + $_.Exception.GetBaseException().Message }
            finally { $sw.Stop(); $client.Dispose() }
            [pscustomobject]@{ Target = "$($t.Label) [$($t.Address)]"; Port = $port; Outcome = $outcome; Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 2) }
        }
    } finally { $listener.Stop() }
}

function Get-FirewallReport {
    param([string]$ProgramPath)
    $profiles = Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
        Select-Object Name, Enabled, DefaultInboundAction, AllowLocalFirewallRules, LogBlocked
    $rules = @()
    $filters = Get-NetFirewallApplicationFilter -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
        Where-Object { $_.Program -and $_.Program -like "*$([IO.Path]::GetFileName($ProgramPath))" }
    foreach ($f in $filters) {
        $r = Get-NetFirewallRule -PolicyStore ActiveStore -AssociatedNetFirewallApplicationFilter $f -ErrorAction SilentlyContinue
        if ($r) { $rules += $r | Select-Object DisplayName, Direction, Action, Enabled, Profile, PolicyStoreSourceType }
    }
    [pscustomobject]@{ Profiles = $profiles; ClientRules = $rules }
}

function Get-SecurityServices {
    Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Where-Object { ($_.Name + ' ' + $_.DisplayName + ' ' + $_.PathName) -match $script:SecurityPattern } |
        Select-Object Name, DisplayName, State, StartMode
}

function Get-ThirdPartyWfpFilterCounts {
    $file = Join-Path $OutDir "wfp-filters-$script:Stamp.xml"
    & netsh wfp show filters file="$file" 2>&1 | Out-Null
    if (-not (Test-Path $file)) { return @() }
    $text = Get-Content $file -Raw
    $names = [regex]::Matches($text, '<name>([^<]+)</name>') | ForEach-Object { $_.Groups[1].Value }
    $names | Where-Object { $_ -match $script:SecurityPattern } | Group-Object | Sort-Object Count -Descending |
        Select-Object @{n = 'FilterName'; e = { $_.Name } }, Count
}

function Invoke-Diagnose {
    Write-Log '=== Diagnose ==='
    $path = Get-HorizonClientPath
    if (-not $path) { Write-Log 'Horizon Client executable not found.' 'ERROR'; Add-Result 'Diagnose' 'Failed' 'Client not found'; return }
    $id = Get-ClientIdentity -Path $path
    $id | Format-List | Out-String | ForEach-Object { Write-Log $_.Trim() }
    if ($id.Signature -ne 'Valid') { Write-Log "Signature is '$($id.Signature)'. Do not proceed until this binary is verified." 'WARN' }

    Write-Log "Self-address TCP probe (timeout $ProbeTimeoutSeconds s per target)..."
    $probe = Test-SelfConnect -TimeoutSeconds $ProbeTimeoutSeconds
    $probe | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Log $_.TrimEnd() }
    $timedOut = @($probe | Where-Object { $_.Outcome -like 'TIMEOUT*' })
    if ($timedOut.Count -gt 0) {
        Write-Log 'Machine-wide filter is silently dropping connections to this machine''s own address. Capture WFP (-CaptureWfp) to name it.' 'WARN'
        Add-Result 'SelfConnectProbe' 'STALL REPRODUCED' (($timedOut | ForEach-Object Target) -join '; ')
    } else {
        Write-Log 'Probe connected everywhere. If the client still stalls, the drop is specific to horizon-client.exe (program rule or per-process EDR policy).'
        Add-Result 'SelfConnectProbe' 'Passed' 'No machine-wide drop for powershell.exe'
    }

    $fw = Get-FirewallReport -ProgramPath $path
    $fw.Profiles | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Log $_.TrimEnd() }
    if ($fw.ClientRules) { $fw.ClientRules | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Log $_.TrimEnd() } }
    else { Write-Log 'No Windows Firewall rule references this program: it falls under the profile default inbound action.' 'WARN' }
    $blocked = @($fw.ClientRules | Where-Object { $_.Action -eq 'Block' -and $_.Enabled -eq 'True' })
    if ($blocked.Count) { Add-Result 'Firewall' 'Block rule present' (($blocked | ForEach-Object DisplayName) -join '; ') }
    elseif (-not $fw.ClientRules) { Add-Result 'Firewall' 'No allow rule' 'Default inbound action applies' }
    else { Add-Result 'Firewall' 'Rules present' "$(@($fw.ClientRules).Count) rule(s)" }

    $svc = Get-SecurityServices
    if ($svc) { $svc | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Log $_.TrimEnd() } }
    $wfp = Get-ThirdPartyWfpFilterCounts
    if ($wfp) {
        Write-Log 'WFP filters registered by security/network products:'
        $wfp | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Log $_.TrimEnd() }
        Add-Result 'WfpFilters' 'Found' (($wfp | ForEach-Object { "$($_.FilterName) x$($_.Count)" }) -join '; ')
    }
}

function Invoke-MeasureLaunch {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    $path = Get-HorizonClientPath
    if (-not $path) { Write-Log 'Client not found.' 'ERROR'; return }
    if (-not $PSCmdlet.ShouldProcess($path, 'Launch, time to main window, then close')) { return }
    Get-Process -Name ([IO.Path]::GetFileNameWithoutExtension($path)) -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Seconds 2
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $p = Start-Process -FilePath $path -PassThru
    $shown = $false
    while ($sw.Elapsed.TotalSeconds -lt 180) {
        $p.Refresh()
        if ($p.HasExited) { break }
        if ($p.MainWindowHandle -ne [IntPtr]::Zero) { $shown = $true; break }
        Start-Sleep -Milliseconds 250
    }
    $sw.Stop()
    if ($shown) { Write-Log ("Main window appeared after {0:N1} s." -f $sw.Elapsed.TotalSeconds); Add-Result 'MeasureLaunch' 'Measured' ("{0:N1} s to main window" -f $sw.Elapsed.TotalSeconds) }
    else { Write-Log 'Main window not detected within 180 s (or process exited).' 'WARN'; Add-Result 'MeasureLaunch' 'No window' 'Timed out or exited' }
    if (-not $p.HasExited) { $p | Stop-Process -Force -ErrorAction SilentlyContinue }
}

function Invoke-WfpCapture {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    $path = Get-HorizonClientPath
    if (-not $path) { Write-Log 'Client not found.' 'ERROR'; return }
    if (-not $PSCmdlet.ShouldProcess('WFP capture + client launch', "Capture $CaptureSeconds s")) { return }
    Push-Location $OutDir
    try {
        & netsh wfp capture start | Out-Null
        Write-Log 'WFP capture started. Launching client...'
        $p = Start-Process -FilePath $path -PassThru
        Start-Sleep -Seconds $CaptureSeconds
        if (-not $p.HasExited) { $p | Stop-Process -Force -ErrorAction SilentlyContinue }
        & netsh wfp capture stop | Out-Null
    } finally { Pop-Location }
    $cab = Join-Path $OutDir 'wfpdiag.cab'
    if (-not (Test-Path $cab)) { Write-Log 'wfpdiag.cab was not produced.' 'ERROR'; Add-Result 'WfpCapture' 'Failed' 'No cab'; return }
    $kept = Join-Path $OutDir "wfpdiag-$script:Stamp.cab"
    Move-Item $cab $kept -Force
    Write-Log "Capture saved: $kept"
    # Best-effort summary: find CLASSIFY_DROP events for the client and resolve the filter that dropped them.
    try {
        $dir = Join-Path $OutDir "wfpdiag-$script:Stamp"
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        & expand.exe -F:* $kept $dir | Out-Null
        $xmlPath = Get-ChildItem $dir -Filter 'wfpdiag.xml' -Recurse | Select-Object -First 1
        $filtersXml = Join-Path $OutDir "wfp-filters-$script:Stamp.xml"
        if (-not (Test-Path $filtersXml)) { & netsh wfp show filters file="$filtersXml" | Out-Null }
        [xml]$diag = Get-Content $xmlPath.FullName -Raw
        [xml]$flt = Get-Content $filtersXml -Raw
        $drops = $diag.SelectNodes("//item[type='FWPM_NET_EVENT_TYPE_CLASSIFY_DROP']") |
            Where-Object { $_.OuterXml -match 'horizon-client|vmware-view' }
        $summary = foreach ($d in $drops) {
            $fid = $d.SelectSingleNode('.//filterId').InnerText
            $f = $flt.SelectSingleNode("//item[filterId='$fid']")
            [pscustomobject]@{
                FilterId = $fid
                Name     = if ($f) { $f.displayData.name } else { '(not resolved)' }
                Provider = if ($f) { $f.providerKey } else { '' }
                Layer    = $d.SelectSingleNode('.//layerId').InnerText
            }
        }
        if ($summary) {
            $out = Join-Path $OutDir "wfp-drop-summary-$script:Stamp.csv"
            $summary | Group-Object FilterId, Name, Provider | ForEach-Object { $_.Group[0] | Select-Object *, @{n = 'Drops'; e = { $_.Count } } } |
                Export-Csv $out -NoTypeInformation
            Import-Csv $out | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Log $_.TrimEnd() }
            Add-Result 'WfpCapture' 'Drops identified' $out
        } else {
            Write-Log 'No client drop events parsed. Give the .cab to the security team (or open it with a WFP analysis tool).' 'WARN'
            Add-Result 'WfpCapture' 'No drops parsed' $kept
        }
    } catch {
        Write-Log "Automatic summary failed: $($_.Exception.Message). Provide $kept to the security team." 'WARN'
        Add-Result 'WfpCapture' 'Summary failed' $kept
    }
}

function Set-HorizonFirewallRule {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    $path = Get-HorizonClientPath
    if (-not $path) { Write-Log 'Client not found.' 'ERROR'; return }
    $name = 'Omnissa Horizon Client - local IPC (TCP)'
    $ownV4 = @(Get-OwnIPv4Addresses) + '127.0.0.1'
    $remote = if ($FirewallScope -eq 'Self') { $ownV4 } else { @('LocalSubnet', '127.0.0.1') }

    $local = Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
        Where-Object { "$($_.AllowLocalFirewallRules)" -eq 'False' }
    if ($local) {
        $gpoFile = Join-Path $OutDir "gpo-firewall-rule-$script:Stamp.txt"
        @(
            'Windows Firewall ignores locally created rules on this machine (GPO: apply local firewall rules = No).',
            'Create this rule in the firewall GPO instead:',
            "  Name: $name", '  Direction: Inbound   Action: Allow   Protocol: TCP   Profiles: Domain, Private, Public',
            "  Program: $path", '  Remote addresses: the machine itself / local subnet (see -FirewallScope)'
        ) | Set-Content $gpoFile
        Write-Log "Local rules are ignored here. GPO-ready definition written to $gpoFile" 'WARN'
        Add-Result 'FirewallRule' 'Needs GPO' $gpoFile
        return
    }

    $existing = Get-NetFirewallRule -DisplayName $name -PolicyStore PersistentStore -ErrorAction SilentlyContinue
    if ($existing) {
        if ($PSCmdlet.ShouldProcess($name, 'Update remote addresses')) { Set-NetFirewallRule -DisplayName $name -RemoteAddress $remote }
        Write-Log "Rule '$name' already exists - addresses refreshed."
    } elseif ($PSCmdlet.ShouldProcess($name, 'Create inbound allow rule')) {
        New-NetFirewallRule -DisplayName $name -Group 'Horizon Startup Fix' -Direction Inbound -Action Allow `
            -Protocol TCP -Program $path -Profile Any -RemoteAddress $remote | Out-Null
        Write-Log "Created inbound allow rule '$name' (scope: $FirewallScope; remote: $($remote -join ', '))."
    }
    Add-Result 'FirewallRule' 'Applied' "$name scope=$FirewallScope"

    if ($FirewallScope -eq 'Self') {
        $refresh = Join-Path $OutDir 'Refresh-HorizonFirewallScope.ps1'
        @'
$name = 'Omnissa Horizon Client - local IPC (TCP)'
$ips = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() |
  Where-Object { $_.OperationalStatus -eq 'Up' -and $_.NetworkInterfaceType -ne 'Loopback' } |
  ForEach-Object { $_.GetIPProperties().UnicastAddresses } |
  Where-Object { $_.Address.AddressFamily -eq 'InterNetwork' -and $_.Address.ToString() -notlike '169.254.*' } |
  ForEach-Object { $_.Address.ToString() }
if (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue) {
  Set-NetFirewallRule -DisplayName $name -RemoteAddress (@($ips) + '127.0.0.1')
}
'@ | Set-Content $refresh -Encoding UTF8
        if ($PSCmdlet.ShouldProcess('Horizon Firewall Scope Refresh', 'Register scheduled tasks (startup + network change)')) {
            $cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$refresh`""
            & schtasks.exe /Create /F /RU SYSTEM /SC ONSTART /TN 'Horizon Firewall Scope Refresh (boot)' /TR $cmd | Out-Null
            & schtasks.exe /Create /F /RU SYSTEM /SC ONEVENT /EC 'Microsoft-Windows-NetworkProfile/Operational' `
                /MO "*[System[(EventID=10000)]]" /TN 'Horizon Firewall Scope Refresh (network)' /TR $cmd | Out-Null
            Write-Log 'Scheduled tasks registered so the rule follows IP address changes.'
        }
    }
}

function Export-SecurityRequest {
    $path = Get-HorizonClientPath
    if (-not $path) { Write-Log 'Client not found.' 'ERROR'; return }
    $id = Get-ClientIdentity -Path $path
    $file = Join-Path $OutDir "security-exclusion-request-$script:Stamp.txt"
    @"
SUBJECT: Request - allow Omnissa Horizon Client local (self-address) TCP traffic; 63-second launch stall

HOST: $env:COMPUTERNAME     DATE: $(Get-Date -Format 'yyyy-MM-dd HH:mm')

BINARY
  Path:    $($id.Path)
  Version: $($id.Version)
  Signer:  $($id.Signer)   (Authenticode status: $($id.Signature))
  SHA256:  $($id.SHA256)

PROBLEM
  On launch the client opens three TCP connections to this machine's own FQDN address on
  ephemeral ports. Each SYN is silently dropped (SYN retransmits at +1/+3/+7/+15 s, failure
  at +21 s, no RST, no accept on the listener). Each failure is followed within milliseconds by
  a successful connection over 127.0.0.1 ('view-localhost'). 3 x 21 s = 63 s of a ~73 s launch.
  Evidence: Procmon capture 2026-10-06 11:22:13-11:23:49 (host 1H8624348Q).

REQUEST
  SentinelOne:  Allow/exclude network inspection and Firewall Control blocking for the
                process above (match by path + signer/SHA256) for TCP between this host's
                own addresses (loopback and its own IPs). Ports are ephemeral - scope by process, not port.
  Symantec DLP: Confirm the endpoint network filter does not inspect/drop local-to-local TCP for this process.
  Firewall:     Inbound allow for the program above, remote = this host's own addresses.
  Please report which control was dropping the traffic (WFP filter name/provider) for the record.

NOT REQUESTED
  No change to scanning of the binary itself, to TLS inspection, or to any external traffic.
"@ | Set-Content $file -Encoding UTF8
    Write-Log "Security request written: $file"
    Add-Result 'SecurityRequest' 'Written' $file
}

# ---------------- main ----------------
if (-not (Test-IsAdministrator)) { Write-Log 'Run this script elevated (Administrator).' 'ERROR'; throw 'Administrator rights required.' }
if ($All) { $Diagnose = $true; $ExportSecurityRequest = $true; $FixFirewallRule = $true }
if (-not ($Diagnose -or $MeasureLaunch -or $CaptureWfp -or $FixFirewallRule -or $ExportSecurityRequest)) {
    Write-Log 'No action selected. Start with -Diagnose -MeasureLaunch (see Get-Help).' 'WARN'
    return
}

Write-Log "Horizon Client loopback-stall tool starting (outputs in $OutDir)."
if ($Diagnose)              { Invoke-Diagnose }
if ($MeasureLaunch -and -not $FixFirewallRule) { Invoke-MeasureLaunch }
if ($CaptureWfp)            { Invoke-WfpCapture }
if ($ExportSecurityRequest) { Export-SecurityRequest }
if ($FixFirewallRule) {
    if ($MeasureLaunch) { Write-Log 'Before fix:'; Invoke-MeasureLaunch }
    Set-HorizonFirewallRule
    if ($MeasureLaunch) { Write-Log 'After fix:'; Invoke-MeasureLaunch }
}

Write-Log 'Done.'
$script:Results | Format-Table -AutoSize
$script:Results | Export-Csv (Join-Path $OutDir 'loopback-stall-results.csv') -NoTypeInformation -Append
