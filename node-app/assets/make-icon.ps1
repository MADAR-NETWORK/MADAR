# Draws the MADAR "M" icon (same geometry as logo.svg) into a multi-size .ico and a 512px PNG.
# Sizes < 256 are classic DIB entries (decode everywhere); 256 is PNG.
param([string]$Out = "$PSScriptRoot\madar.ico", [string]$Png = "$PSScriptRoot\madar-512.png")
Add-Type -AssemblyName System.Drawing

function RoundRect($x, $y, $w, $h, $r) {
    $p = New-Object Drawing.Drawing2D.GraphicsPath
    $p.AddArc($x, $y, 2 * $r, 2 * $r, 180, 90); $p.AddArc($x + $w - 2 * $r, $y, 2 * $r, 2 * $r, 270, 90)
    $p.AddArc($x + $w - 2 * $r, $y + $h - 2 * $r, 2 * $r, 2 * $r, 0, 90); $p.AddArc($x, $y + $h - 2 * $r, 2 * $r, 2 * $r, 90, 90)
    $p.CloseFigure(); $p
}

function Draw-Logo([int]$s) {
    $bmp = New-Object Drawing.Bitmap $s, $s
    $g = [Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'; $g.PixelOffsetMode = 'HighQuality'; $g.Clear([Drawing.Color]::Transparent)
    $f = $s / 256.0
    $bg = New-Object Drawing.Drawing2D.LinearGradientBrush((New-Object Drawing.PointF(0, 0)), (New-Object Drawing.PointF($s, $s)),
        [Drawing.Color]::FromArgb(255, 15, 181, 166), [Drawing.Color]::FromArgb(255, 47, 91, 234))
    $g.FillPath($bg, (RoundRect (8 * $f) (8 * $f) (240 * $f) (240 * $f) (60 * $f)))
    if ($s -ge 48) {   # the faint orbit only where it can be seen
        $orbit = New-Object Drawing.Pen ([Drawing.Color]::FromArgb(46, 255, 255, 255)), (6 * $f)
        $g.DrawEllipse($orbit, (36 * $f), (42 * $f), (184 * $f), (184 * $f))
    }
    $w = [Math]::Max(2.2, 24 * $f)
    $pen = New-Object Drawing.Pen ([Drawing.Color]::White), $w
    $pen.StartCap = 'Round'; $pen.EndCap = 'Round'; $pen.LineJoin = 'Round'
    $pts = @((New-Object Drawing.PointF((68 * $f), (180 * $f))), (New-Object Drawing.PointF((68 * $f), (86 * $f))),
             (New-Object Drawing.PointF((128 * $f), (146 * $f))), (New-Object Drawing.PointF((188 * $f), (86 * $f))),
             (New-Object Drawing.PointF((188 * $f), (180 * $f))))
    $g.DrawLines($pen, [Drawing.PointF[]]$pts)
    $r = [Math]::Max(2.0, 14 * $f)
    $g.FillEllipse((New-Object Drawing.SolidBrush ([Drawing.Color]::FromArgb(255, 255, 197, 61))), (174 * $f - $r), (54 * $f - $r), (2 * $r), (2 * $r))
    $g.Dispose(); $bmp
}

$big = Draw-Logo 512; $big.Save($Png, [Drawing.Imaging.ImageFormat]::Png); $big.Dispose()

# Status dot for the tray variants: bottom-right, with a ring in the background colour so it reads at 16px.
function Draw-Tray([int]$s, [Drawing.Color]$dot) {
    $bmp = Draw-Logo $s
    $g = [Drawing.Graphics]::FromImage($bmp); $g.SmoothingMode = 'AntiAlias'
    $d = [Math]::Max(6, [int]($s * 0.46)); $x = $s - $d; $y = $s - $d
    $g.FillEllipse((New-Object Drawing.SolidBrush ([Drawing.Color]::FromArgb(255, 11, 16, 32))), $x - 1, $y - 1, $d + 1, $d + 1)
    $g.FillEllipse((New-Object Drawing.SolidBrush $dot), $x + 1, $y + 1, $d - 3, $d - 3)
    $g.Dispose(); $bmp
}

function Write-Ico([string]$path, [int[]]$sizes, [scriptblock]$draw) {
    $entries = foreach ($s in $sizes) {
        $bmp = & $draw $s
        if ($s -ge 256) { $ms = New-Object IO.MemoryStream; $bmp.Save($ms, [Drawing.Imaging.ImageFormat]::Png); $bmp.Dispose(); , $ms.ToArray(); continue }
        $ms = New-Object IO.MemoryStream; $bw = New-Object IO.BinaryWriter($ms)
        $bw.Write([UInt32]40); $bw.Write([Int32]$s); $bw.Write([Int32]($s * 2)); $bw.Write([UInt16]1); $bw.Write([UInt16]32)
        $bw.Write([UInt32]0); $bw.Write([UInt32]0); $bw.Write([Int32]0); $bw.Write([Int32]0); $bw.Write([UInt32]0); $bw.Write([UInt32]0)
        for ($y = $s - 1; $y -ge 0; $y--) { for ($x = 0; $x -lt $s; $x++) { $c = $bmp.GetPixel($x, $y); $bw.Write([byte]$c.B); $bw.Write([byte]$c.G); $bw.Write([byte]$c.R); $bw.Write([byte]$c.A) } }
        $bw.Write((New-Object byte[] ([int]([Math]::Ceiling($s / 32.0) * 4) * $s)))
        $bmp.Dispose(); , $ms.ToArray()
    }
    $ico = New-Object IO.MemoryStream; $w = New-Object IO.BinaryWriter($ico)
    $w.Write([UInt16]0); $w.Write([UInt16]1); $w.Write([UInt16]$sizes.Count)
    $offset = 6 + 16 * $sizes.Count
    for ($i = 0; $i -lt $sizes.Count; $i++) {
        $dd = if ($sizes[$i] -ge 256) { 0 } else { $sizes[$i] }
        $w.Write([byte]$dd); $w.Write([byte]$dd); $w.Write([byte]0); $w.Write([byte]0)
        $w.Write([UInt16]1); $w.Write([UInt16]32); $w.Write([UInt32]$entries[$i].Length); $w.Write([UInt32]$offset)
        $offset += $entries[$i].Length
    }
    foreach ($e in $entries) { $w.Write($e) }
    [IO.File]::WriteAllBytes($path, $ico.ToArray())
}

$trayDir = Split-Path -Parent $Out
foreach ($pair in @(@('good', @(34, 197, 94)), @('warn', @(245, 165, 36)), @('bad', @(239, 68, 68)), @('idle', @(148, 163, 184)))) {
    $c = [Drawing.Color]::FromArgb(255, $pair[1][0], $pair[1][1], $pair[1][2])
    Write-Ico (Join-Path $trayDir "tray-$($pair[0]).ico") @(16, 20, 24, 32) { param($s) Draw-Tray $s $c }.GetNewClosure()
}

$sizes = 16, 24, 32, 48, 64, 128, 256
$entries = foreach ($s in $sizes) {
    $bmp = Draw-Logo $s
    if ($s -ge 256) { $ms = New-Object IO.MemoryStream; $bmp.Save($ms, [Drawing.Imaging.ImageFormat]::Png); $bmp.Dispose(); , $ms.ToArray(); continue }
    $ms = New-Object IO.MemoryStream; $bw = New-Object IO.BinaryWriter($ms)
    $bw.Write([UInt32]40); $bw.Write([Int32]$s); $bw.Write([Int32]($s * 2)); $bw.Write([UInt16]1); $bw.Write([UInt16]32)
    $bw.Write([UInt32]0); $bw.Write([UInt32]0); $bw.Write([Int32]0); $bw.Write([Int32]0); $bw.Write([UInt32]0); $bw.Write([UInt32]0)
    for ($y = $s - 1; $y -ge 0; $y--) { for ($x = 0; $x -lt $s; $x++) { $c = $bmp.GetPixel($x, $y); $bw.Write([byte]$c.B); $bw.Write([byte]$c.G); $bw.Write([byte]$c.R); $bw.Write([byte]$c.A) } }
    $bw.Write((New-Object byte[] ([int]([Math]::Ceiling($s / 32.0) * 4) * $s)))
    $bmp.Dispose(); , $ms.ToArray()
}
$ico = New-Object IO.MemoryStream; $w = New-Object IO.BinaryWriter($ico)
$w.Write([UInt16]0); $w.Write([UInt16]1); $w.Write([UInt16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $d = if ($sizes[$i] -ge 256) { 0 } else { $sizes[$i] }
    $w.Write([byte]$d); $w.Write([byte]$d); $w.Write([byte]0); $w.Write([byte]0)
    $w.Write([UInt16]1); $w.Write([UInt16]32); $w.Write([UInt32]$entries[$i].Length); $w.Write([UInt32]$offset)
    $offset += $entries[$i].Length
}
foreach ($e in $entries) { $w.Write($e) }
[IO.File]::WriteAllBytes($Out, $ico.ToArray())
"wrote $Out and $Png"
