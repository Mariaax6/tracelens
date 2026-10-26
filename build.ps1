param([string]$JdkHome = $env:JAVA_HOME)
$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    $javac = if ($JdkHome) { Join-Path $JdkHome 'bin/javac.exe' } else { 'javac' }
    $java = if ($JdkHome) { Join-Path $JdkHome 'bin/java.exe' } else { 'java' }
    $jar = if ($JdkHome) { Join-Path $JdkHome 'bin/jar.exe' } else { 'jar' }
    New-Item -ItemType Directory -Force build/classes,build/tests,dist | Out-Null
    $sources = @(Get-ChildItem src -Recurse -Filter *.java | ForEach-Object FullName)
    & $javac --release 17 -encoding UTF-8 -d build/classes @sources
    if ($LASTEXITCODE -ne 0) { throw 'Compilation failed' }
    $tests = @(Get-ChildItem test -Recurse -Filter *.java | ForEach-Object FullName)
    & $javac --release 17 -encoding UTF-8 -cp build/classes -d build/tests @tests
    if ($LASTEXITCODE -ne 0) { throw 'Test compilation failed' }
    & $java -cp 'build/classes;build/tests' portfolio.tracelens.Tests
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
    & $jar ('-J-Djava.io.tmpdir=' + (Join-Path $PSScriptRoot 'build')) --create --file dist/tracelens.jar --main-class portfolio.tracelens.Main -C build/classes .
    if ($LASTEXITCODE -ne 0) { throw 'Packaging failed' }
    Write-Host 'Built dist/tracelens.jar'
} finally { Pop-Location }
