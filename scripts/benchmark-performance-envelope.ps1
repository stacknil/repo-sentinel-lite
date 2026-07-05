param(
    [int[]] $FileCounts = @(1000, 10000),
    [int] $ChangedFileCount = 50,
    [string] $WorkRoot = ".benchmark-work",
    [switch] $KeepWorkRoot
)

$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$ResolvedWorkRoot = Join-Path $RepoRoot $WorkRoot

if (-not (Test-Path $ResolvedWorkRoot)) {
    New-Item -ItemType Directory -Path $ResolvedWorkRoot | Out-Null
}

function New-SyntheticRepo {
    param(
        [string] $Root,
        [int] $Count
    )

    if (Test-Path $Root) {
        $resolvedTarget = Resolve-Path $Root
        if (-not $resolvedTarget.Path.StartsWith((Resolve-Path $ResolvedWorkRoot).Path)) {
            throw "Refusing to delete outside benchmark work root: $Root"
        }
        Remove-Item -LiteralPath $Root -Recurse -Force
    }

    New-Item -ItemType Directory -Path $Root | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $Root "src") | Out-Null
    Set-Content -Path (Join-Path $Root "README.md") -Value "# Synthetic benchmark" -Encoding UTF8
    Set-Content -Path (Join-Path $Root "LICENSE") -Value "MIT" -Encoding UTF8
    Set-Content -Path (Join-Path $Root ".gitignore") -Value "*.tmp" -Encoding UTF8

    for ($index = 1; $index -le $Count; $index++) {
        $fileName = "file-{0:D5}.txt" -f $index
        $filePath = Join-Path (Join-Path $Root "src") $fileName
        Set-Content `
            -Path $filePath `
            -Value "synthetic benchmark line $index" `
            -Encoding UTF8
    }
}

function Invoke-RepoSentinelScan {
    param(
        [string[]] $Arguments
    )

    $command = @("-m", "repo_sentinel.cli") + $Arguments
    $elapsed = Measure-Command {
        & python @command | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "repo-sentinel exited with $LASTEXITCODE"
        }
    }
    return [math]::Round($elapsed.TotalSeconds, 3)
}

Write-Output "files,full_scan_seconds,changed_files,changed_scan_seconds"

try {
    foreach ($count in $FileCounts) {
        $fixtureRoot = Join-Path $ResolvedWorkRoot ("repo-{0}" -f $count)
        $reportPath = Join-Path $ResolvedWorkRoot ("report-{0}.json" -f $count)
        $changedReportPath = Join-Path $ResolvedWorkRoot ("report-{0}-changed.json" -f $count)

        New-SyntheticRepo -Root $fixtureRoot -Count $count

        $fullSeconds = Invoke-RepoSentinelScan -Arguments @(
            "scan",
            "--output",
            $reportPath,
            $fixtureRoot
        )

        $changedPaths = @()
        for ($index = 1; $index -le ([math]::Min($ChangedFileCount, $count)); $index++) {
            $changedPaths += ("src/file-{0:D5}.txt" -f $index)
        }

        $changedSeconds = Invoke-RepoSentinelScan -Arguments (
            @(
                "scan",
                "--changed-files",
                "--output",
                $changedReportPath,
                $fixtureRoot
            ) + $changedPaths
        )

        Write-Output ("{0},{1},{2},{3}" -f $count, $fullSeconds, $changedPaths.Count, $changedSeconds)
    }
}
finally {
    if (-not $KeepWorkRoot -and (Test-Path $ResolvedWorkRoot)) {
        $resolvedTarget = Resolve-Path $ResolvedWorkRoot
        if ($resolvedTarget.Path.StartsWith((Resolve-Path $RepoRoot).Path)) {
            Remove-Item -LiteralPath $ResolvedWorkRoot -Recurse -Force
        }
    }
}
