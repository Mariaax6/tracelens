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
    function Expect([int]$Want, [string]$Text, [string[]]$Arguments) {
        $out = (& $java -jar dist/tracelens.jar @Arguments 2>&1 | Out-String)
        if ($LASTEXITCODE -ne $Want) { throw "Expected exit $Want but got ${LASTEXITCODE}: $($Arguments -join ' ')`n$out" }
        if (-not $out.Contains($Text)) { throw "Output lacks '$Text': $($Arguments -join ' ')`n$out" }
        Write-Host "ok   exit $LASTEXITCODE   $($Arguments -join ' ')"
    }
    Expect 0 'RECORDS=33 DECODED=33 FLOWS=19 ALERTS=1' @('examples/demo.pcap', 'reports/demo')
    Expect 1 'ALERTS=1' @('examples/demo.pcap', 'reports/demo-ci', '--fail-on-alert')
    Expect 0 'RECORDS=20 DECODED=20 FLOWS=20 ALERTS=0' @('examples/slow-diverse.pcap', 'reports/slow-diverse', '--fail-on-alert')
    Expect 0 'RECORDS=9 DECODED=4 FLOWS=3 ALERTS=0' @('examples/coverage.pcap', 'reports/coverage')
    Expect 2 'Not a classic PCAP' @('README.md', 'reports/none')
    Write-Host 'Open reports/demo/report.html to inspect the results.'
} finally { Pop-Location }
