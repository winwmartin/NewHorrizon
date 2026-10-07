<#
.SYNOPSIS
    Traces which ports Horizon Client (horizon-client.exe) listens on and connects to during
    startup, flags connection attempts that go unanswered (blocked), and documents them.

.DESCRIPTION
    Launches the client (or attaches to a running one) and, for the client and its child
    processes, samples the TCP table every -PollMilliseconds. It records:

      1. LISTENING PORTS   every port the client listens on, the address it is bound to
                           (0.0.0.0 vs 127.0.0.1 matters), and when it appeared.
      2. CONNECTION ATTEMPTS  every outbound connection with its state history. An attempt
                           that sits in SynSent for >= -BlockedThresholdSeconds and never
                           reaches Established is reported as BLOCKED / UNANSWERED. For each
                           one the script notes whether the target is this machine's own
                           address and whether a listener exists on that port (and where
                           it is bound).
      3. WHO DROPPED IT    (needs elevation) While the client starts it temporarily turns on
                           * Windows Firewall "log dropped packets", and
                           * the "Filtering Platform Packet Drop" / "Filtering Platform
                             Connection" failure audits (Security events 5152 / 5157),
                           then reads them back, resolves each drop's filter ID to a filter
                           name with `netsh wfp show filters`, and lists them. All logging
                           settings are restored afterwards, even if the run is interrupted.

    A packet dropped silently (no reset) shows up as an attempt stuck in SynSent. If Windows
    Firewall or any other WFP filter dropped it you will see the filter by name. If the attempt
    is stuck but NO drop is logged anywhere, the drop happened below what Windows can log
    (typically a third-party driver) - the report says so.

    Outputs go to <OutRoot>\PortTrace-<timestamp>\ :
      report.txt  attempts.csv  listeners.csv  timeline.csv
      firewall-drops.csv  wfp-drops.csv  wfp-filters.xml

.PARAMETER ProcessName       Process to trace (without .exe). Default: horizon-client.
.PARAMETER ClientPath        Full path to the client. Auto-discovered if omitted.
.PARAMETER AttachToRunning   Do not launch; trace an already-running instance.
.PARAMETER DurationSeconds   Maximum trace length. Default 120.
.PARAMETER PollMilliseconds  Sampling interval. Default 500.
.PARAMETER BlockedThresholdSeconds  SynSent time that counts as blocked. Default 3.
.PARAMETER GraceAfterWindowSeconds  Keep tracing this long after the main window appears. Default 5.
.PARAMETER SkipFirewallLog   Do not touch Windows Firewall logging.
.PARAMETER SkipWfpAudit      Do not touch the Filtering Platform audit policy.
.PARAMETER KeepClientOpen    Leave the client running when the trace ends.

.EXAMPLE
    .\Trace-HorizonClientPorts.ps1

.EXAMPLE
    .\Trace-HorizonClientPorts.ps1 -AttachToRunning -DurationSeconds 60 -SkipWfpAudit

.NOTES
    Run elevated on Windows 11 for full results. Without elevation the socket trace still works
    but the firewall-log and WFP-audit parts are skipped. Sampling can miss attempts shorter than
    the poll interval; the 20+ second stalls this tool targets are captured easily. If group
    policy manages firewall logging or audit policy, the local change may be overridden - the
    report says when that happens. -WhatIf previews only the logging changes (firewall log and
    audit policy); the client is still launched and traced.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$ProcessName = 'horizon-client',
    [string]$ClientPath,
    [switch]$AttachToRunning,
    [int]$DurationSeconds = 120,
    [int]$PollMilliseconds = 500,
    [int]$BlockedThresholdSeconds = 3,
    [int]$GraceAfterWindowSeconds = 5,
    [switch]$SkipFirewallLog,
    [switch]$SkipWfpAudit,
    [switch]$KeepClientOpen,
    [string]$OutRoot = "$env:ProgramData\HorizonStartupFix"
)

$SecurityPattern = 'Sentinel|Symantec|Vontu|EDPA|Eracent|CrowdStrike|Tanium|Zscaler|Netskope|Forcepoint|McAfee|Trellix|Cisco|AnyConnect|GlobalProtect'
$AuditGuids = @{ PacketDrop = '{0CCE9225-69AE-11D9-BED3-505054503030}'; Connection = '{0CCE9226-69AE-11D9-BED3-505054503030}' }

# =====================================================================
#  Pure analysis helpers (no Windows-only cmdlets - unit-testable)
# =====================================================================

function Update-Tracker {
    <# Folds one poll of socket rows into the tracker. Rows need: PID, State, LocalAddress,
       LocalPort, RemoteAddress, RemotePort. Returns new timeline events. #>
    param($Tracker, $Rows, [datetime]$Now, [datetime]$Start, [scriptblock]$ListenerLookup)
    $events = [System.Collections.Generic.List[pscustomobject]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    $elapsed = [math]::Round(($Now - $Start).TotalSeconds, 2)
    foreach ($r in $Rows) {
        $key = "{0}|{1}:{2}|{3}:{4}" -f $r.PID, $r.LocalAddress, $r.LocalPort, $r.RemoteAddress, $r.RemotePort
        [void]$seen.Add($key)
        $state = "$($r.State)"
        if (-not $Tracker.ContainsKey($key)) {
            $Tracker[$key] = [pscustomobject]@{
                Key = $key; PID = $r.PID; LocalAddress = $r.LocalAddress; LocalPort = [int]$r.LocalPort
                RemoteAddress = $r.RemoteAddress; RemotePort = [int]$r.RemotePort
                FirstSeen = $Now; LastSeen = $Now; State = $state; Gone = $false; GoneAt = $null
                SynFirst = $null; SynLast = $null; EstablishedAt = $null; Listener = $null
            }
            $events.Add([pscustomobject]@{ ElapsedSec = $elapsed; PID = $r.PID; Event = "New:$state"; Local = "$($r.LocalAddress):$($r.LocalPort)"; Remote = "$($r.RemoteAddress):$($r.RemotePort)" })
        }
        $t = $Tracker[$key]
        $t.LastSeen = $Now
        if ($t.State -ne $state) {
            $events.Add([pscustomobject]@{ ElapsedSec = $elapsed; PID = $r.PID; Event = "$($t.State)->$state"; Local = "$($t.LocalAddress):$($t.LocalPort)"; Remote = "$($t.RemoteAddress):$($t.RemotePort)" })
            $t.State = $state
        }
        if ($state -eq 'SynSent') {
            if (-not $t.SynFirst) {
                $t.SynFirst = $Now
                if ($ListenerLookup) { $t.Listener = & $ListenerLookup $t.RemotePort }
            }
            $t.SynLast = $Now
        }
        if ($state -eq 'Established' -and -not $t.EstablishedAt) { $t.EstablishedAt = $Now }
    }
    foreach ($k in @($Tracker.Keys)) {
        $t = $Tracker[$k]
        if (-not $t.Gone -and -not $seen.Contains($k)) {
            $t.Gone = $true; $t.GoneAt = $Now
            $events.Add([pscustomobject]@{ ElapsedSec = $elapsed; PID = $t.PID; Event = "Gone(last=$($t.State))"; Local = "$($t.LocalAddress):$($t.LocalPort)"; Remote = "$($t.RemoteAddress):$($t.RemotePort)" })
        }
    }
    return $events
}

function Get-AttemptSummary {
    param($Tracker, [int]$ThresholdSeconds, [string[]]$OwnAddresses, [int]$PollMs)
    foreach ($t in $Tracker.Values | Where-Object { $_.SynFirst }) {
        $syn = [math]::Round(($t.SynLast - $t.SynFirst).TotalSeconds + ($PollMs / 1000), 1)
        $established = [bool]$t.EstablishedAt
        $verdict = if (-not $established -and $syn -ge $ThresholdSeconds) { 'BLOCKED/UNANSWERED' }
                   elseif ($established -and $syn -ge $ThresholdSeconds) { 'SLOW' }
                   elseif ($established) { 'OK' } else { 'FAILED-FAST' }
        $self = $OwnAddresses -contains "$($t.RemoteAddress)"
        $listener = if ($t.Listener) { ($t.Listener -join '; ') } else { '(none found)' }
        [pscustomobject]@{
            Verdict       = $verdict
            PID           = $t.PID
            Local         = "$($t.LocalAddress):$($t.LocalPort)"
            Remote        = "$($t.RemoteAddress):$($t.RemotePort)"
            RemoteIsSelf  = $self
            SynSentSec    = $syn
            Outcome       = if ($established) { 'Established' } elseif ($t.Gone) { 'Disappeared (timeout/failed)' } else { "Still $($t.State)" }
            ListenerOnTargetPort = $listener
            FirstSeen     = $t.SynFirst.ToString('HH:mm:ss.fff')
        }
    }
}

function Get-ListenerSummary {
    param($Tracker)
    $Tracker.Values | Where-Object { $_.State -eq 'Listen' -or $_.RemotePort -eq 0 } | Sort-Object FirstSeen | ForEach-Object {
        [pscustomobject]@{
            PID = $_.PID; BoundAddress = "$($_.LocalAddress)"; Port = $_.LocalPort
            Scope = switch -Wildcard ("$($_.LocalAddress)") { '0.0.0.0' { 'All IPv4 interfaces' } '::' { 'All IPv6 interfaces' } '127.*' { 'Loopback only' } '::1' { 'Loopback only' } default { 'Single interface' } }
            FirstSeen = $_.FirstSeen.ToString('HH:mm:ss.fff')
        }
    }
}

function Read-FirewallLog {
    param([string[]]$Lines, [datetime]$Since, [int[]]$Pids, [int[]]$Ports)
    $fields = @()
    foreach ($line in $Lines) {
        if ($line -like '#Fields:*') { $fields = ($line -replace '^#Fields:\s*', '') -split '\s+'; continue }
        if ($line.StartsWith('#') -or -not $line.Trim() -or -not $fields) { continue }
        $v = $line -split '\s+'
        if ($v.Count -lt $fields.Count) { continue }
        $o = @{}; for ($i = 0; $i -lt $fields.Count; $i++) { $o[$fields[$i]] = $v[$i] }
        if ($o['action'] -ne 'DROP') { continue }
        try { $ts = [datetime]::ParseExact("$($o['date']) $($o['time'])", 'yyyy-MM-dd HH:mm:ss', $null) } catch { continue }
        if ($ts -lt $Since) { continue }
        $pidMatch = $o.ContainsKey('pid') -and ($Pids -contains [int]($o['pid'] -replace '-', '0') -and $o['pid'] -ne '-')
        $portMatch = ($Ports -contains [int]($o['src-port'] -replace '-', '0')) -or ($Ports -contains [int]($o['dst-port'] -replace '-', '0'))
        if ($pidMatch -or $portMatch) {
            [pscustomobject]@{
                Time = $ts.ToString('HH:mm:ss'); Protocol = $o['protocol']; Path = $o['path']; PID = $o['pid']
                Source = "$($o['src-ip']):$($o['src-port'])"; Destination = "$($o['dst-ip']):$($o['dst-port'])"
                TcpFlags = $o['tcpflags']; Match = if ($pidMatch) { 'ClientPID' } else { 'PortMatch' }
            }
        }
    }
}

function Get-Verdict {
    param($Attempts, $WfpDrops, $FwDrops, [bool]$AuditActive, [bool]$FwLogActive)
    $lines = [System.Collections.Generic.List[string]]::new()
    $blocked = @($Attempts | Where-Object { $_.Verdict -eq 'BLOCKED/UNANSWERED' })
    if (-not $blocked) {
        $lines.Add('No blocked/unanswered connection attempts were observed in this run.')
        $lines.Add('If the client still started slowly, the delay is not a dropped connection - re-check with Procmon (Duration column) for CRL, DNS or disk waits.')
        return $lines
    }
    $totalSec = [math]::Round(($blocked | Measure-Object SynSentSec -Sum).Sum, 0)
    $self = @($blocked | Where-Object RemoteIsSelf).Count
    $lines.Add("$($blocked.Count) connection attempt(s) were blocked/unanswered, ~$totalSec s of waiting in total ($self targeted this machine's own address).")
    $noListener = @($blocked | Where-Object { $_.ListenerOnTargetPort -eq '(none found)' }).Count
    if ($noListener -lt $blocked.Count) { $lines.Add('A listener DOES exist on the targeted port for some attempts, so the SYN was dropped on its way to a live listener - a filter, not a missing service.') }
    if ($noListener -gt 0) { $lines.Add("$noListener attempt(s) had no listener on the target port at detection time; a missing listener normally produces an instant reset, so a 20 s hang still points to a silent drop.") }

    $named = @($WfpDrops | Where-Object { $_.FilterName -and $_.FilterName -ne '(unresolved)' } | Group-Object FilterName, FilterId | Sort-Object Count -Descending)
    if ($named) {
        $lines.Add('Dropping filter(s) identified from the Filtering Platform audit:')
        foreach ($g in $named) {
            $f = $g.Group[0]
            $owner = if ($f.FilterName -match $SecurityPattern) { 'THIRD-PARTY SECURITY PRODUCT' }
                     elseif ($f.FilterName -match 'Block|Default|Windows Firewall|WFP|Boot') { 'Windows Firewall / built-in' } else { 'review name' }
            $lines.Add("  - '$($f.FilterName)' (filter id $($f.FilterId), layer $($f.Layer)), $($g.Count) drop(s) -> $owner")
        }
    } elseif (@($FwDrops).Count) {
        $lines.Add("Windows Firewall logged $(@($FwDrops).Count) DROP entr(ies) for the client's PID or ports: Windows Firewall is dropping the traffic. Add an inbound allow rule for the program.")
    } else {
        if ($AuditActive -or $FwLogActive) {
            $lines.Add('Attempts were blocked but NO drop was logged by Windows Firewall or the Filtering Platform audit.')
            $lines.Add('That points below what Windows can log - typically a third-party security driver or an agent that discards packets itself (for example the SentinelOne agent). Ask that product''s owner to check its network/firewall control for this process.')
        } else {
            $lines.Add('Drop logging was not active (run elevated and do not use -SkipFirewallLog/-SkipWfpAudit) so the dropper cannot be named from this run.')
        }
    }
    return $lines
}

# =====================================================================
#  Windows-only plumbing
# =====================================================================

function Test-IsAdministrator {
    $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-ClientPathAuto {
    if ($ClientPath -and (Test-Path $ClientPath)) { return (Resolve-Path $ClientPath).Path }
    @("$env:ProgramFiles\Omnissa\Omnissa Horizon Client\$ProcessName.exe",
      "${env:ProgramFiles(x86)}\Omnissa\Omnissa Horizon Client\$ProcessName.exe",
      "$env:ProgramFiles\VMware\VMware Horizon View Client\vmware-view.exe",
      "${env:ProgramFiles(x86)}\VMware\VMware Horizon View Client\vmware-view.exe") |
        Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
}

function Get-OwnAddressList {
    $list = [System.Collections.Generic.List[string]]::new()
    $list.Add('127.0.0.1'); $list.Add('::1')
    [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | ForEach-Object {
        $_.GetIPProperties().UnicastAddresses | ForEach-Object { $list.Add(($_.Address.ToString() -replace '%.*$', '')) }
    }
    $list | Select-Object -Unique
}

function Get-DescendantPids {
    param([int[]]$RootPids)
    $set = [System.Collections.Generic.HashSet[int]]::new()
    foreach ($r in $RootPids) { [void]$set.Add($r) }
    $procs = Get-CimInstance Win32_Process -Property ProcessId, ParentProcessId -ErrorAction SilentlyContinue
    $changed = $true
    while ($changed) {
        $changed = $false
        foreach ($p in $procs) { if ($set.Contains([int]$p.ParentProcessId) -and $set.Add([int]$p.ProcessId)) { $changed = $true } }
    }
    return @($set)   # callers rebuild a HashSet; returning the set itself would be unrolled by the pipeline
}

function Get-AuditSetting {
    param([string]$Guid)
    $csv = & auditpol.exe /get /subcategory:$Guid /r 2>$null | ConvertFrom-Csv
    $setting = "$(@($csv)[0].'Inclusion Setting')"
    [pscustomobject]@{ Success = ($setting -match 'Success'); Failure = ($setting -match 'Failure') }
}
function Set-AuditSetting {
    param([string]$Guid, [bool]$Success, [bool]$Failure)
    $s = if ($Success) { 'enable' } else { 'disable' }; $f = if ($Failure) { 'enable' } else { 'disable' }
    & auditpol.exe /set /subcategory:$Guid /success:$s /failure:$f | Out-Null
}

function Get-WfpFilterMap {
    param([string]$XmlPath)
    $map = @{}
    & netsh.exe wfp show filters file="$XmlPath" 2>&1 | Out-Null
    if (-not (Test-Path $XmlPath)) { return $map }
    try {
        [xml]$x = Get-Content $XmlPath -Raw
        foreach ($n in $x.SelectNodes('//item[filterId]')) {
            $id = $n.SelectSingleNode('filterId').InnerText
            $name = $n.SelectSingleNode('displayData/name'); $prov = $n.SelectSingleNode('providerKey')
            $map[$id] = [pscustomobject]@{ Name = if ($name) { $name.InnerText } else { '' }; Provider = if ($prov) { $prov.InnerText } else { '' } }
        }
    } catch { }
    return $map
}

function Read-WfpDropEvents {
    param([datetime]$Since, [int[]]$Ports, $FilterMap)
    $evts = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 5152, 5157; StartTime = $Since } -ErrorAction SilentlyContinue
    foreach ($e in $evts) {
        $d = @{}
        ([xml]$e.ToXml()).Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
        $app = "$($d['Application'])"
        $appMatch = $app -match 'horizon-client|vmware-view'
        $portMatch = ($Ports -contains [int]($d['SourcePort'] -replace '\D', '0')) -or ($Ports -contains [int]($d['DestPort'] -replace '\D', '0'))
        if (-not ($appMatch -or $portMatch)) { continue }
        $fid = "$($d['FilterRTID'])"
        $f = $FilterMap[$fid]
        [pscustomobject]@{
            Time = $e.TimeCreated.ToString('HH:mm:ss.fff'); EventId = $e.Id; Application = $app
            Direction = $d['Direction']; Source = "$($d['SourceAddress']):$($d['SourcePort'])"; Destination = "$($d['DestAddress']):$($d['DestPort'])"
            Protocol = $d['Protocol']; Layer = $d['LayerName']; FilterId = $fid
            FilterName = if ($f -and $f.Name) { $f.Name } else { '(unresolved)' }; Provider = if ($f) { $f.Provider } else { '' }
            Match = if ($appMatch) { 'ClientApp' } else { 'PortMatch' }
        }
    }
}

# =====================================================================
#  Main
# =====================================================================
if ($MyInvocation.InvocationName -eq '.') { return }   # allow dot-sourcing for tests

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$outDir = Join-Path $OutRoot "PortTrace-$stamp"
New-Item -ItemType Directory -Path $outDir -Force | Out-Null
$isAdmin = Test-IsAdministrator
if (-not $isAdmin) { Write-Warning 'Not elevated: firewall-log and WFP-audit capture are skipped. Socket tracing still runs.' }
$doFw = $isAdmin -and -not $SkipFirewallLog
$doAudit = $isAdmin -and -not $SkipWfpAudit

$tracker = @{}
$timeline = [System.Collections.Generic.List[pscustomobject]]::new()
$own = @(Get-OwnAddressList)
$origFw = $null; $origAudit = @{}; $fwLogPath = $null
$fwActive = $false; $auditActive = $false
$proc = $null; $windowAt = $null; $notes = [System.Collections.Generic.List[string]]::new()
$listenerLookup = {
    param($port)
    Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue | ForEach-Object {
        $pn = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName
        "$($_.LocalAddress):$($_.LocalPort) (pid $($_.OwningProcess) $pn)"
    }
}

try {
    # ---- enable drop logging (restored in finally) ----
    if ($doFw -and $PSCmdlet.ShouldProcess('Windows Firewall profiles', 'Temporarily enable dropped-packet logging')) {
        $origFw = Get-NetFirewallProfile -PolicyStore PersistentStore | Select-Object Name, LogBlocked
        Set-NetFirewallProfile -Profile Domain, Private, Public -LogBlocked True -ErrorAction Stop
        $active = Get-NetFirewallProfile -PolicyStore ActiveStore
        $fwActive = -not ($active | Where-Object { "$($_.LogBlocked)" -ne 'True' })
        if (-not $fwActive) { $notes.Add('Windows Firewall logging is controlled by group policy; local setting was overridden, so firewall drop log may be empty.') }
        $lf = ($active | Select-Object -First 1).LogFileName
        $fwLogPath = if ($lf -and "$lf" -ne 'NotConfigured') { [Environment]::ExpandEnvironmentVariables("$lf") } else { "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log" }
    }
    if ($doAudit -and $PSCmdlet.ShouldProcess('Audit policy', 'Temporarily enable Filtering Platform failure auditing')) {
        foreach ($k in $AuditGuids.Keys) { $origAudit[$k] = Get-AuditSetting $AuditGuids[$k]; Set-AuditSetting $AuditGuids[$k] $origAudit[$k].Success $true }
        $auditActive = $true
    }

    # ---- start / attach ----
    $start = Get-Date
    if ($AttachToRunning) {
        $proc = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $proc) { throw "No running '$ProcessName' process found." }
    } else {
        $path = Get-ClientPathAuto
        if (-not $path) { throw 'Horizon Client executable not found. Use -ClientPath.' }
        Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | Stop-Process -Force
        Start-Sleep -Seconds 2
        $start = Get-Date
        $proc = Start-Process -FilePath $path -PassThru
    }
    Write-Host "Tracing PID $($proc.Id) for up to $DurationSeconds s..."

    # ---- sampling loop ----
    $pidSet = [System.Collections.Generic.HashSet[int]]::new(); [void]$pidSet.Add($proc.Id)
    $lastTree = [datetime]::MinValue; $exitedAt = $null
    while (((Get-Date) - $start).TotalSeconds -lt $DurationSeconds) {
        $now = Get-Date
        if (($now - $lastTree).TotalSeconds -ge 2) {
            $roots = @($proc.Id) + @(Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | ForEach-Object Id)
            $pidSet = [System.Collections.Generic.HashSet[int]]::new([int[]]@(Get-DescendantPids -RootPids $roots)); $lastTree = $now
        }
        $rows = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $pidSet.Contains([int]$_.OwningProcess) } |
            ForEach-Object { [pscustomobject]@{ PID = $_.OwningProcess; State = "$($_.State)"; LocalAddress = "$($_.LocalAddress)"; LocalPort = $_.LocalPort; RemoteAddress = "$($_.RemoteAddress)"; RemotePort = $_.RemotePort } }
        $ev = Update-Tracker -Tracker $tracker -Rows $rows -Now $now -Start $start -ListenerLookup $listenerLookup
        foreach ($e in $ev) { $timeline.Add($e) }

        $proc.Refresh()
        if (-not $windowAt -and -not $proc.HasExited -and $proc.MainWindowHandle -ne [IntPtr]::Zero) {
            $windowAt = $now
            $timeline.Add([pscustomobject]@{ ElapsedSec = [math]::Round(($now - $start).TotalSeconds, 2); PID = $proc.Id; Event = 'MainWindowShown'; Local = ''; Remote = '' })
        }
        if ($proc.HasExited -and -not $exitedAt) { $exitedAt = $now }
        if ($windowAt -and ($now - $windowAt).TotalSeconds -ge $GraceAfterWindowSeconds) { break }
        if ($exitedAt -and ($now - $exitedAt).TotalSeconds -ge $GraceAfterWindowSeconds) { break }
        Start-Sleep -Milliseconds $PollMilliseconds
    }
    $end = Get-Date
    $udp = Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Where-Object { $pidSet.Contains([int]$_.OwningProcess) } |
        ForEach-Object { "$($_.LocalAddress):$($_.LocalPort) (pid $($_.OwningProcess))" }

    if (-not $KeepClientOpen -and -not $AttachToRunning -and $proc -and -not $proc.HasExited) { $proc | Stop-Process -Force -ErrorAction SilentlyContinue }

    # ---- analysis ----
    $attempts = @(Get-AttemptSummary -Tracker $tracker -ThresholdSeconds $BlockedThresholdSeconds -OwnAddresses $own -PollMs $PollMilliseconds)
    $listeners = @(Get-ListenerSummary -Tracker $tracker)
    $ports = @($listeners.Port) + @($attempts | ForEach-Object { [int](($_.Remote -split ':')[-1]) }) + @($attempts | ForEach-Object { [int](($_.Local -split ':')[-1]) }) | Where-Object { $_ } | Select-Object -Unique
    $fwDrops = @(); $wfpDrops = @()
    if ($fwActive -and $fwLogPath -and (Test-Path $fwLogPath)) {
        $fwDrops = @(Read-FirewallLog -Lines (Get-Content $fwLogPath -ErrorAction SilentlyContinue) -Since $start.AddSeconds(-2) -Pids @($pidSet) -Ports $ports)
    }
    if ($auditActive) {
        $filterMap = Get-WfpFilterMap -XmlPath (Join-Path $outDir 'wfp-filters.xml')
        $wfpDrops = @(Read-WfpDropEvents -Since $start.AddSeconds(-2) -Ports $ports -FilterMap $filterMap)
    }
    $verdict = Get-Verdict -Attempts $attempts -WfpDrops $wfpDrops -FwDrops $fwDrops -AuditActive $auditActive -FwLogActive $fwActive

    # ---- documents ----
    $attempts   | Export-Csv (Join-Path $outDir 'attempts.csv') -NoTypeInformation
    $listeners  | Export-Csv (Join-Path $outDir 'listeners.csv') -NoTypeInformation
    $timeline   | Export-Csv (Join-Path $outDir 'timeline.csv') -NoTypeInformation
    $fwDrops    | Export-Csv (Join-Path $outDir 'firewall-drops.csv') -NoTypeInformation
    $wfpDrops   | Export-Csv (Join-Path $outDir 'wfp-drops.csv') -NoTypeInformation

    $fmt = { param($o) if ($o) { ($o | Format-Table -AutoSize | Out-String -Width 220).TrimEnd() } else { '(none)' } }
    $report = @()
    $report += "HORIZON CLIENT PORT TRACE  -  $env:COMPUTERNAME  -  $($start.ToString('yyyy-MM-dd HH:mm:ss'))"
    $report += "Process: $ProcessName (PID $($proc.Id))   Traced: $([math]::Round(($end - $start).TotalSeconds, 1)) s   Poll: $PollMilliseconds ms"
    if ($windowAt) { $report += "Main window appeared after $([math]::Round(($windowAt - $start).TotalSeconds, 1)) s" } else { $report += 'Main window did not appear during the trace.' }
    $report += "Own addresses: $($own -join ', ')"
    $report += ''; $report += '== VERDICT =='; $report += $verdict
    $report += ''; $report += '== PORTS THE CLIENT LISTENS ON (TCP) =='; $report += (& $fmt $listeners)
    if ($udp) { $report += ''; $report += 'UDP endpoints: ' + ($udp -join '; ') }
    $report += ''; $report += '== CONNECTION ATTEMPTS THAT USED SynSent (sorted by wait) =='
    $report += (& $fmt ($attempts | Sort-Object SynSentSec -Descending))
    $report += ''; $report += '== WINDOWS FIREWALL DROP LOG (client PID / observed ports) =='; $report += (& $fmt $fwDrops)
    $report += ''; $report += '== FILTERING PLATFORM DROPS (events 5152/5157, filter resolved) =='; $report += (& $fmt ($wfpDrops | Select-Object Time, EventId, Direction, Source, Destination, Layer, FilterId, FilterName, Match))
    if ($notes.Count) { $report += ''; $report += '== NOTES =='; $report += $notes }
    $report += ''; $report += 'Files: attempts.csv listeners.csv timeline.csv firewall-drops.csv wfp-drops.csv wfp-filters.xml'
    $report | Set-Content (Join-Path $outDir 'report.txt') -Encoding UTF8
    $report | ForEach-Object { Write-Host $_ }
    Write-Host "`nSaved to $outDir"
}
finally {
    # ---- always restore logging settings ----
    if ($origFw) {
        foreach ($p in $origFw) { try { Set-NetFirewallProfile -Profile $p.Name -LogBlocked $p.LogBlocked -ErrorAction Stop } catch { Write-Warning "Could not restore firewall logging for $($p.Name): $_" } }
    }
    foreach ($k in $origAudit.Keys) { try { Set-AuditSetting $AuditGuids[$k] $origAudit[$k].Success $origAudit[$k].Failure } catch { Write-Warning "Could not restore audit setting $k : $_" } }
}
