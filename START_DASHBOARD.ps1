# Local, tokenless Unified Pentest Console. No hard-coded Windows user or drive.
param([int]$Port = 5210, [switch]$Stop, [switch]$NoBrowser)
$ErrorActionPreference='Stop'
$Root=Split-Path -Parent $MyInvocation.MyCommand.Path
$State=Join-Path $Root 'pentest\unified\dashboard.pid'
$PortState=Join-Path $Root 'pentest\unified\dashboard.port'
# A saved custom port is used by -Stop when the caller did not supply -Port.
if ($Stop -and -not $PSBoundParameters.ContainsKey('Port') -and (Test-Path $PortState)) {
    $savedPort=0
    [void][int]::TryParse((Get-Content $PortState -Raw).Trim(),[ref]$savedPort)
    if ($savedPort -ge 1024 -and $savedPort -le 65535) { $Port=$savedPort }
}
if ($Port -lt 1024 -or $Port -gt 65535) { throw 'Port must be between 1024 and 65535' }
if ($Stop) {
    if (!(Test-Path $State)) { Write-Host 'No managed dashboard PID'; exit 0 }
    $recordedPid=0
    [void][int]::TryParse((Get-Content $State -Raw).Trim(),[ref]$recordedPid)
    $listeners=Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    $owned=@($listeners | Where-Object { $_.LocalAddress -eq '127.0.0.1' })
    $stopped=$false
    foreach($listener in $owned) {
        $proc=Get-CimInstance Win32_Process -Filter "ProcessId=$($listener.OwningProcess)" -ErrorAction SilentlyContinue
        if ($proc -and $proc.ProcessId -eq $recordedPid -and $proc.CommandLine -match 'pentest\.unified\.server') {
            Stop-Process -Id $proc.ProcessId -ErrorAction Stop
            $stopped=$true
            Write-Host "Stopped dashboard PID $($proc.ProcessId)"
            break
        }
    }
    if (-not $stopped) { Write-Warning 'Recorded PID is not a verified dashboard listener; nothing terminated' }
    if ($stopped) {
        Remove-Item $State -Force -ErrorAction SilentlyContinue
        Remove-Item $PortState -Force -ErrorAction SilentlyContinue
    }
    exit 0
}
$existing=Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
if ($existing) {
    $owner=Get-CimInstance Win32_Process -Filter "ProcessId=$($existing.OwningProcess)" -ErrorAction SilentlyContinue
    if ($owner.CommandLine -notmatch 'pentest\.unified\.server') { throw "Port $Port already used by an unrelated process. Pick another port." }
    if ($existing.LocalAddress -ne '127.0.0.1' -or -not (Test-Path $State) -or
        (Get-Content $State -Raw).Trim() -ne [string]$existing.OwningProcess) {
        throw "Port $Port belongs to a dashboard without this installation's verified local PID. Pick another port."
    }
    $Port | Set-Content -Encoding ascii $PortState
    Write-Host "Reusing dashboard at http://127.0.0.1:$Port/"
} else {
    if (!(Get-Command py -ErrorAction SilentlyContinue)) { throw 'Python 3 launcher is not installed' }
    $PythonPath=(& py -3 -c 'import sys;print(sys.executable)' | Select-Object -Last 1).Trim()
    if (-not (Test-Path -LiteralPath $PythonPath)) { throw 'Python 3 runtime not found' }
    $proc=Start-Process -FilePath $PythonPath -ArgumentList @('-m','pentest.unified.server','--port',"$Port",'--no-browser') -WorkingDirectory $Root -PassThru -WindowStyle Hidden
    $proc.Id | Set-Content -Encoding ascii $State
    $Port | Set-Content -Encoding ascii $PortState
    $ready=$false
    for($i=0;$i -lt 40;$i++){
       Start-Sleep -Milliseconds 250
       try { $r=Invoke-WebRequest -Uri "http://127.0.0.1:$Port/api/summary" -UseBasicParsing -TimeoutSec 2; if($r.StatusCode -eq 200){$ready=$true;break} }catch{}
       if($proc.HasExited){break}
    }
    if(-not $ready) { throw 'New dashboard did not become ready; inspect its local startup environment' }
    Write-Host "Dashboard ready: http://127.0.0.1:$Port/"
}
if (-not $NoBrowser){Start-Process "http://127.0.0.1:$Port/"}
