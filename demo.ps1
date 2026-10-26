param([string]$JdkHome = $env:JAVA_HOME)
$ErrorActionPreference = 'Stop'
if (-not $JdkHome) {
    $compiler = Get-Command javac -ErrorAction SilentlyContinue
    if ($compiler) { $JdkHome = Split-Path (Split-Path $compiler.Source) }
}
if (-not $JdkHome) { throw "Specify -JdkHome with a JDK 17+ installation, for example 'C:\Program Files\Java\jdk-21'." }
& (Join-Path $PSScriptRoot 'build.ps1') -JdkHome $JdkHome
$java = Join-Path $JdkHome 'bin/java.exe'
Push-Location $PSScriptRoot
try {
    & $java -cp 'build/classes;build/tests' portfolio.tracelens.Demo examples
    if ($LASTEXITCODE -ne 0) { throw 'Fixture generation failed' }
    & $java -jar dist/tracelens.jar examples/demo.pcap reports/demo
    if ($LASTEXITCODE -ne 0) { throw 'Analysis failed' }
    Write-Host 'Open reports/demo/report.html to inspect the results.'
} finally { Pop-Location }
