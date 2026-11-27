$ErrorActionPreference = "Stop"
$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$refs = Join-Path ${env:ProgramFiles(x86)} 'Reference Assemblies\Microsoft\Framework\.NETFramework\v4.8.1'
if (!(Test-Path (Join-Path $refs 'PresentationCore.dll'))) {
  $refs = Join-Path ${env:ProgramFiles(x86)} 'Reference Assemblies\Microsoft\Framework\.NETFramework\v4.8'
}
$assemblies = @('mscorlib.dll','System.dll','System.Core.dll','System.Drawing.dll','System.Windows.Forms.dll','System.Runtime.Serialization.dll','System.ServiceModel.dll','System.Xaml.dll','WindowsBase.dll','PresentationCore.dll','PresentationFramework.dll','System.Xml.dll')
$references = @()
foreach ($assembly in $assemblies) {
  $ref = Join-Path $refs $assembly
  if (!(Test-Path $ref)) { throw "Required .NET reference assembly unavailable" }
  $references += "/reference:$ref"
}
$source = (Resolve-Path 'probes\netfx481_cad_prerequisites.cs').Path
$buildDir = (Resolve-Path 'build').Path
foreach ($arch in @('x86','x64')) {
  $destination = Join-Path $buildDir "netfx481_cad_prerequisites_$arch.exe"
  & $csc /nologo /noconfig /nostdlib+ "/platform:$arch" /target:exe @references "/out:$destination" $source
  if ($LASTEXITCODE -ne 0 -or !(Test-Path -LiteralPath $destination -PathType Leaf)) { throw "CAD prerequisite fixture compile failed" }
}
@'
import json, subprocess
from pathlib import Path
from scripts.netfx481_cad_prerequisites import parse, MODES
result = {}
for bits, arch in ((32, "x86"), (64, "x64")):
    fixture = Path("build/netfx481_cad_prerequisites_" + arch + ".exe").resolve()
    result[str(bits)] = {}
    for mode in MODES:
        try:
            p = subprocess.run([str(fixture), mode], capture_output=True, timeout=30, check=False)
            result[str(bits)][mode] = parse(p.stdout, p.returncode, mode, bits)
        except subprocess.TimeoutExpired:
            result[str(bits)][mode] = {"result":"TIMEOUT", "native":False, "hresult":"NOT_VERIFIED"}
    assert result[str(bits)]["core"]["result"] == "PASS", "Native Windows CLR control failed"
Path("build/netfx481-cad-windows-reference.json").write_text(json.dumps(result, sort_keys=True), encoding="ascii")
print("Windows CAD reference " + json.dumps(result, sort_keys=True))
'@ | python -
if ($LASTEXITCODE -ne 0) { throw "CAD reference validation failed" }
