# Builds the MADAR Node 2.0 Windows installer: target\public\MADAR-Setup-<ver>-windows-x64.exe
# plus latest.json (template for the site) and SHA256SUMS.txt.
# Payload: node binary (current release build), app, chain spec + fingerprint, UI, icon, config, VERSION.
# No dashboard files, credentials, node keys or data.
$ErrorActionPreference = 'Stop'
$repo    = Split-Path -Parent $PSScriptRoot
$out     = Join-Path $repo 'target\public'
$stage   = Join-Path $out 'stage'
$version = (Select-String -Path "$repo\node-app\Cargo.toml" -Pattern '^version = "(.+)"').Matches[0].Groups[1].Value
$setupName = "MADAR-Setup-$version-windows-x64.exe"
# Where the site will serve the files (latest.json points here; the app only accepts the same origin).
$siteBase = 'https://madar-network.com/downloads'

Push-Location $repo
try {
    cmd /c "cargo build --offline --release -p madar-app 2>&1" | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'madar-app build failed' }
    if (-not (Test-Path "$repo\target\release\madar-node.exe")) { throw 'target\release\madar-node.exe missing' }

    if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
    New-Item -ItemType Directory -Force "$stage\bin", "$stage\chain", "$stage\ui" | Out-Null
    Copy-Item "$repo\target\release\madar-node.exe" "$stage\bin\"
    Copy-Item "$repo\target\release\madar-app.exe"  "$stage\bin\"
    Copy-Item "$repo\madar-spec.json"               "$stage\chain\"
    Copy-Item "$repo\node-app\ui\index.html"        "$stage\ui\"
    Copy-Item "$repo\node-app\assets\logo.svg"      "$stage\ui\"
    Copy-Item "$repo\node-app\assets\madar.ico"     "$stage\"
    Copy-Item "$repo\node-app\assets\tray-*.ico"    "$stage\"
    $spec = (Get-FileHash "$stage\chain\madar-spec.json" -Algorithm SHA256).Hash.ToLower()
    [IO.File]::WriteAllText("$stage\chain\spec.sha256", "$spec  madar-spec.json`r`n")
    # registry_url stays empty until the registry endpoint on madar-network.com is decided.
    $config = [ordered]@{ registry_url = ''; latest_url = "$siteBase/latest.json" } | ConvertTo-Json
    [IO.File]::WriteAllText("$stage\config.json", $config)
    $node = (Get-FileHash "$stage\bin\madar-node.exe" -Algorithm SHA256).Hash.ToLower()
    $app  = (Get-FileHash "$stage\bin\madar-app.exe" -Algorithm SHA256).Hash.ToLower()
    $ver = @"
MADAR Node $version
platform: windows-x64 (Windows 10/11)
role: full (non-voting)
bootnode: /ip4/188.241.241.253/tcp/30333/p2p/12D3KooWDAr7FDtAeUx51zowWytNKeeuQfB5B2cyF4bZmDEp9j9K
built: $((Get-Date).ToString('yyyy-MM-dd HH:mm zzz'))
madar-spec.json sha256: $spec
madar-node.exe sha256: $node
madar-app.exe sha256: $app
"@
    [IO.File]::WriteAllText("$stage\VERSION", $ver.Replace("`r`n", "`n").Replace("`n", "`r`n"))

    $bad = Get-ChildItem -Recurse -File $stage | Where-Object { $_.Name -match 'node-key|credential|keystore|dashboard|secret|\.enc$' -or $_.FullName -match '\\data\\' }
    if ($bad) { throw "forbidden files in payload: $($bad.FullName -join ', ')" }

    # Container: magic, count, then per file: u16 name len, name, sha256, u64 len, bytes. Then raw Deflate.
    $files = Get-ChildItem -Recurse -File $stage | Sort-Object FullName
    $ms = New-Object IO.MemoryStream
    $bw = New-Object IO.BinaryWriter($ms)
    $bw.Write([Text.Encoding]::ASCII.GetBytes("MDRPAY1`0"))
    $bw.Write([UInt32]$files.Count)
    $sha = [Security.Cryptography.SHA256]::Create()
    foreach ($f in $files) {
        $rel = $f.FullName.Substring($stage.Length + 1).Replace('\', '/')
        $nameBytes = [Text.Encoding]::UTF8.GetBytes($rel)
        $data = [IO.File]::ReadAllBytes($f.FullName)
        $bw.Write([UInt16]$nameBytes.Length); $bw.Write($nameBytes)
        $bw.Write($sha.ComputeHash($data)); $bw.Write([UInt64]$data.Length); $bw.Write($data)
    }
    $bw.Flush()
    $payload = Join-Path $out 'payload.deflate'
    $fs = [IO.File]::Create($payload)
    $ds = New-Object IO.Compression.DeflateStream($fs, [IO.Compression.CompressionLevel]::Optimal)
    $ms.Position = 0; $ms.CopyTo($ds); $ds.Close(); $fs.Close()
    "payload: $($files.Count) files, $([math]::Round($ms.Length / 1MB, 1)) MB -> $([math]::Round((Get-Item $payload).Length / 1MB, 1)) MB"

    $env:MADAR_PAYLOAD_FILE = $payload
    cmd /c "cargo build --offline --release -p madar-setup 2>&1" | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'madar-setup build failed' }
    Remove-Item Env:\MADAR_PAYLOAD_FILE

    $setup = Join-Path $out $setupName
    Copy-Item "$repo\target\release\madar-setup.exe" $setup -Force
    $setupSha = (Get-FileHash $setup -Algorithm SHA256).Hash.ToLower()
    $latest = [ordered]@{
        version = $version
        url     = "$siteBase/$setupName"
        sha256  = $setupSha
        notes   = [ordered]@{ en = ''; ar = '' }
    }
    # optional fast-sync snapshot (from make-snapshot.ps1), covered by the same signature
    $snap = Get-ChildItem $out -Filter 'snapshot-*.zip' | Sort-Object LastWriteTime | Select-Object -Last 1
    if ($snap) {
        $latest.snapshot = [ordered]@{
            url    = "$siteBase/$($snap.Name)"
            sha256 = (Get-FileHash $snap.FullName -Algorithm SHA256).Hash.ToLower()
            block  = [int64]($snap.BaseName -replace 'snapshot-', '')
        }
    }
    $latestPath = Join-Path $out 'latest.json'
    [IO.File]::WriteAllText($latestPath, ($latest | ConvertTo-Json -Depth 4))
    # sign (the app rejects an unsigned or tampered latest.json)
    cmd /c "cargo build --offline --release -p madar-app --bin madar-release-sign 2>&1" | Out-Null
    $key = 'H:\MADAR-Release-Keys\update-signing.key'
    if (-not (Test-Path $key)) { throw "update-signing key missing: $key" }
    & "$repo\target\release\madar-release-sign.exe" sign $key $latestPath
    if ($LASTEXITCODE -ne 0) { throw 'signing latest.json failed' }
    [IO.File]::WriteAllText((Join-Path $out 'SHA256SUMS.txt'), "$setupSha  $setupName`r`n")
    Remove-Item $payload
    Get-Item $setup | Select-Object FullName, Length
    "setup sha256: $setupSha"
    "spec  sha256: $spec"
} finally { Pop-Location }
