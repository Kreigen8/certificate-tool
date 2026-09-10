param([string]$Python = 'python')
$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    & $Python -m unittest discover -p 'test_*.py' -v
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed; build stopped.' }
    & $Python -m PyInstaller --noconfirm --distpath release --workpath build cer_tool_gui.spec
    if ($LASTEXITCODE -ne 0) { throw 'EXE build failed.' }
    Get-FileHash -LiteralPath 'release\cer_tool_gui.exe' -Algorithm SHA256
} finally {
    Pop-Location
}
