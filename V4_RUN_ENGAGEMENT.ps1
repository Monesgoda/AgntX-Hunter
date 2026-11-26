param(
    [Parameter(Mandatory=$true)][string]$Engagement,
    [string]$ArtifactsDir = '',
    [switch]$LiveRecon,
    [switch]$ExecuteAgents
)
$ErrorActionPreference='Stop'
$Root=Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $Root
try {
    py -3 SETUP_V4.py
    if ($LASTEXITCODE -ne 0) { throw 'setup failed' }
    py -3 -m pentest.framework.cli init-db
    if ($LASTEXITCODE -ne 0) { throw 'DB failed' }
    $argsList=@('-3','-m','pentest.framework.cli','run','--engagement',$Engagement)
    if ($ArtifactsDir -ne '') { $argsList+=@('--artifacts-dir',$ArtifactsDir) }
    if ($LiveRecon) { $argsList+='--live' }
    & py @argsList
    if ($LASTEXITCODE -ne 0) { throw 'Authorized recon/queue failed' }
    $dispatchArgs=@('-3','-m','pentest.framework.cli','dispatch','--engagement',$Engagement,'--max-tasks','8','--workers','2')
    if ($ExecuteAgents) { $dispatchArgs+='--execute' }
    & py @dispatchArgs
    if ($LASTEXITCODE -ne 0) { throw 'One or more dispatched tasks failed; review status/logs.' }
    if (-not $ExecuteAgents) { Write-Host 'Dry run completed. Use -ExecuteAgents only for explicitly authorized active testing.' }
} finally { Pop-Location }
