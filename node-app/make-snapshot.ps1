# Builds a fast-sync snapshot for MADAR Node 2.0: target\public\snapshot-<block>.zip
# A temporary node syncs on the local SSD with EXACTLY the app's pruning settings, is stopped, and only
# chains\<id>\db is zipped — never chains\<id>\network (node identity) or any keystore.
$ErrorActionPreference = 'Continue'
$repo = Split-Path -Parent $PSScriptRoot
$out  = Join-Path $repo 'target\public'
$work = Join-Path $env:LOCALAPPDATA 'MADAR-snapshot-work'
$node = Join-Path $repo 'target\release\madar-node.exe'
$door = '/ip4/188.241.241.253/tcp/30333/p2p/12D3KooWDAr7FDtAeUx51zowWytNKeeuQfB5B2cyF4bZmDEp9j9K'
$rpc  = 42998
New-Item -ItemType Directory -Force $work, $out | Out-Null
if (Test-Path "$work\node") { cmd /c "rmdir /s /q `"$work\node`"" }

$a = @('--chain', "`"$repo\madar-spec.json`"", '--base-path', "`"$work\node`"", '--name', 'madar-snapshot',
       '--listen-addr', '/ip4/127.0.0.1/tcp/40998', '--rpc-port', $rpc, '--rpc-methods', 'safe',
       '--no-prometheus', '--no-telemetry', '--no-mdns', '--bootnodes', $door, '--reserved-nodes', $door,
       # must match the app (node-app/src/main.rs start_node): RocksDB records the pruning mode
       '--state-pruning', '256', '--blocks-pruning', '4096', '--db-cache', '128')
$p = Start-Process -FilePath $node -ArgumentList $a -WindowStyle Hidden -RedirectStandardError "$work\node.log" -RedirectStandardOutput "$work\node.out.log" -PassThru
function Rpc($m, $params = @()) {
    $b = @{ jsonrpc = '2.0'; id = 1; method = $m; params = $params } | ConvertTo-Json -Compress
    (Invoke-RestMethod -Uri "http://127.0.0.1:$rpc" -Method Post -ContentType 'application/json' -Body $b -TimeoutSec 3).result
}
$deadline = (Get-Date).AddMinutes(15); $best = 0
while ((Get-Date) -lt $deadline -and -not $p.HasExited) {
    Start-Sleep 4
    try {
        $h = Rpc 'system_health'; $best = [Convert]::ToInt64((Rpc 'chain_getHeader').number, 16)
        "sync: #$best peers=$($h.peers) syncing=$($h.isSyncing)"
        if ($h.peers -gt 0 -and -not $h.isSyncing -and $best -gt 0) { break }
    } catch {}
}
Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue; Start-Sleep 3
if ($best -le 0) { throw 'snapshot node did not sync' }

$chains = Get-ChildItem "$work\node\chains" -Directory
$stage = Join-Path $work 'stage'; if (Test-Path $stage) { cmd /c "rmdir /s /q `"$stage`"" }
foreach ($c in $chains) {
    New-Item -ItemType Directory -Force "$stage\chains\$($c.Name)" | Out-Null
    robocopy "$($c.FullName)\db" "$stage\chains\$($c.Name)\db" /E /NFL /NDL /NJH /NJS /NP | Out-Null
}
$bad = Get-ChildItem -Recurse $stage -File | Where-Object { $_.FullName -match '\\network\\|keystore|secret_' }
if ($bad) { throw "refusing: identity/key files in snapshot: $($bad.FullName -join ', ')" }
Get-ChildItem $out -Filter 'snapshot-*.zip' | Remove-Item -Force
$zip = Join-Path $out "snapshot-$best.zip"
Compress-Archive -Path "$stage\chains" -DestinationPath $zip -CompressionLevel Optimal
cmd /c "rmdir /s /q `"$work`""
Get-Item $zip | Select-Object FullName, @{n='MB';e={[math]::Round($_.Length/1MB,1)}}
"block: $best"
"sha256: " + (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
