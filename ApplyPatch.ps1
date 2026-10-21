# SPDX-License-Identifier: Apache-2.0
param(
    [string]$GameExe = '',
    [switch]$Restore
)

$ErrorActionPreference = 'Stop'

function BytesFromHex([string]$Hex) {
    if (($Hex.Length % 2) -ne 0) { throw 'Invalid hexadecimal byte sequence.' }
    [byte[]]$Result = New-Object byte[] ($Hex.Length / 2)
    for ($i = 0; $i -lt $Result.Length; $i++) {
        $Result[$i] = [Convert]::ToByte($Hex.Substring($i * 2, 2), 16)
    }
    return ,$Result
}

function TestBytesAt([byte[]]$Data, [int]$Offset, [byte[]]$Bytes) {
    if ($Offset -lt 0 -or ($Offset + $Bytes.Length) -gt $Data.Length) { return $false }
    for ($i = 0; $i -lt $Bytes.Length; $i++) {
        if ($Data[$Offset + $i] -ne $Bytes[$i]) { return $false }
    }
    return $true
}

function AssertWindowsExe([byte[]]$Data) {
    if ($Data.Length -lt 0x40 -or $Data[0] -ne 0x4D -or $Data[1] -ne 0x5A) {
        throw 'Not a valid Windows EXE (MZ header missing).'
    }
    $PeOffset = [BitConverter]::ToInt32($Data, 0x3C)
    if ($PeOffset -lt 0 -or ($PeOffset + 4) -gt $Data.Length -or
        $Data[$PeOffset] -ne 0x50 -or $Data[$PeOffset + 1] -ne 0x45 -or
        $Data[$PeOffset + 2] -ne 0 -or $Data[$PeOffset + 3] -ne 0) {
        throw 'Not a valid Windows EXE (PE header missing).'
    }
}

function FileSha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function BytesSha256([byte[]]$Data) {
    $Sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return [BitConverter]::ToString($Sha.ComputeHash($Data)).Replace('-', '').ToLowerInvariant()
    } finally {
        $Sha.Dispose()
    }
}

$Segments = @(
    @{ Offset = 0x7EE77;   Before = 'FF1594815200'; After = 'E80575050090' },
    @{ Offset = 0xD6381;   Before = 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'; After = '8b4c24048b54240885c9741285d2740b8a028801424184c075f6c3c60100c3' },
    @{ Offset = 0x5A8A370; Before = '793A'; After = '790A' }
)

try {
    if ([string]::IsNullOrWhiteSpace($GameExe)) {
        $GameExe = Join-Path $PSScriptRoot 'HakuokiWin.exe'
    }
    $GameExe = [System.IO.Path]::GetFullPath($GameExe)
    if ([System.IO.Path]::GetFileName($GameExe) -ine 'HakuokiWin.exe') {
        throw 'Expected HakuokiWin.exe. Refusing to modify another file.'
    }
    $Backup = $GameExe + '.pre-savefix.bak'
    $Temp = $GameExe + '.savefix.tmp'

    # Compile the signatures once, and reject any accidental length mismatch.
    foreach ($Part in $Segments) {
        $Part.BeforeBytes = BytesFromHex $Part.Before
        $Part.AfterBytes = BytesFromHex $Part.After
        if ($Part.BeforeBytes.Length -ne $Part.AfterBytes.Length) {
            throw ('Invalid patch layout at offset 0x{0:X}.' -f $Part.Offset)
        }
    }

    if ($Restore) {
        if (!(Test-Path -LiteralPath $Backup -PathType Leaf)) {
            throw 'Original backup not found. Nothing was restored.'
        }
        [byte[]]$BackupData = [System.IO.File]::ReadAllBytes($Backup)
        AssertWindowsExe $BackupData
        foreach ($Part in $Segments) {
            if (!(TestBytesAt $BackupData $Part.Offset $Part.BeforeBytes)) {
                throw ('Backup has unexpected bytes at 0x{0:X}. No changes made.' -f $Part.Offset)
            }
        }
        $BackupHash = FileSha256 $Backup
        if ((BytesSha256 $BackupData) -ne $BackupHash) {
            throw 'Backup changed while being checked. No changes made.'
        }

        if (!(Test-Path -LiteralPath $GameExe -PathType Leaf)) {
            [System.IO.File]::Copy($Backup, $GameExe, $false)
            if ((FileSha256 $GameExe) -ne $BackupHash) {
                throw 'Restore verification failed. Backup is preserved.'
            }
            Write-Host 'RESTORE SUCCESS: Original EXE recovered from backup.' -ForegroundColor Green
            exit 0
        }

        $CurrentHash = FileSha256 $GameExe
        if ($CurrentHash -eq $BackupHash) {
            Write-Host 'Already restored; no changes needed.' -ForegroundColor Green
            exit 0
        }

        # The installed EXE must equal this exact backup + these exact patch bytes.
        # This prevents an old backup from overwriting an unrelated or updated EXE.
        foreach ($Part in $Segments) {
            for ($i = 0; $i -lt $Part.AfterBytes.Length; $i++) {
                $BackupData[$Part.Offset + $i] = $Part.AfterBytes[$i]
            }
        }
        if ($CurrentHash -ne (BytesSha256 $BackupData)) {
            throw 'The current EXE differs from the backup beyond this patch. Refusing to overwrite it.'
        }
        [System.IO.File]::Copy($Backup, $GameExe, $true)
        if ((FileSha256 $GameExe) -ne $BackupHash) {
            throw 'Restore verification failed. Backup is preserved; restore manually if needed.'
        }
        Write-Host 'RESTORE SUCCESS: Original EXE restored from backup.' -ForegroundColor Green
        exit 0
    }

    if (!(Test-Path -LiteralPath $GameExe -PathType Leaf)) {
        throw 'HakuokiWin.exe not found. Extract the patch files into the game folder.'
    }
    $OriginalHash = FileSha256 $GameExe
    [byte[]]$Data = [System.IO.File]::ReadAllBytes($GameExe)
    AssertWindowsExe $Data
    if ((BytesSha256 $Data) -ne $OriginalHash) {
        throw 'Game EXE changed while being read. No changes made.'
    }

    # No hard-coded whole-file hash: only the bytes relevant to this patch are checked.
    $PatchedParts = 0
    foreach ($Part in $Segments) {
        if (TestBytesAt $Data $Part.Offset $Part.AfterBytes) {
            $PatchedParts++
        } elseif (!(TestBytesAt $Data $Part.Offset $Part.BeforeBytes)) {
            throw ('Unsupported EXE: unexpected bytes at offset 0x{0:X}. No changes made.' -f $Part.Offset)
        }
    }
    if ($PatchedParts -eq $Segments.Count) {
        Write-Host 'Already patched; no changes needed.' -ForegroundColor Green
        exit 0
    }
    if ($PatchedParts -ne 0) {
        throw 'Partially patched EXE detected. No changes made. Restore the original first.'
    }
    if (Test-Path -LiteralPath $Temp) {
        throw 'Temporary patch file already exists. Check it before trying again.'
    }

    # Verify or create a backup of exactly the EXE being patched.
    if (Test-Path -LiteralPath $Backup) {
        if ((FileSha256 $Backup) -ne $OriginalHash) {
            throw 'Existing backup does not match this original EXE. No changes made.'
        }
    } else {
        [System.IO.File]::Copy($GameExe, $Backup, $false)
        if ((FileSha256 $Backup) -ne $OriginalHash) {
            throw 'Backup integrity check failed. Game EXE unchanged.'
        }
    }

    foreach ($Part in $Segments) {
        for ($i = 0; $i -lt $Part.AfterBytes.Length; $i++) {
            $Data[$Part.Offset + $i] = $Part.AfterBytes[$i]
        }
    }
    $ExpectedPatchedHash = BytesSha256 $Data
    $OverwriteAttempted = $false
    try {
        [System.IO.File]::WriteAllBytes($Temp, $Data)
        if ((FileSha256 $Temp) -ne $ExpectedPatchedHash) {
            throw 'Generated patch verification failed. Original EXE unchanged.'
        }
        if ((FileSha256 $GameExe) -ne $OriginalHash) {
            throw 'Game EXE changed before patch installation. No changes made.'
        }
        $OverwriteAttempted = $true
        [System.IO.File]::Copy($Temp, $GameExe, $true)
        if ((FileSha256 $GameExe) -ne $ExpectedPatchedHash) {
            throw 'Post-copy verification failed.'
        }
    } catch {
        if ($OverwriteAttempted) {
            try {
                [System.IO.File]::Copy($Backup, $GameExe, $true)
                if ((FileSha256 $GameExe) -eq $OriginalHash) {
                    Write-Host 'Original EXE automatically restored from backup.' -ForegroundColor Yellow
                } else {
                    Write-Host 'WARNING: Auto-restoration failed verification; restore backup manually.' -ForegroundColor Red
                }
            } catch {
                Write-Host ('WARNING: Auto-restoration failed: ' + $_.Exception.Message) -ForegroundColor Red
                Write-Host ('Original backup remains at: ' + $Backup) -ForegroundColor Yellow
            }
        }
        throw
    } finally {
        if (Test-Path -LiteralPath $Temp) { Remove-Item -LiteralPath $Temp -Force }
    }
    Write-Host 'PATCH SUCCESS: HakuokiWin.exe was updated.' -ForegroundColor Green
    Write-Host ('Original backup: ' + $Backup)
    Write-Host 'Launch the game normally through Steam and test Save.'
} catch {
    Write-Host ('ERROR: ' + $_.Exception.Message) -ForegroundColor Red
    exit 1
}
