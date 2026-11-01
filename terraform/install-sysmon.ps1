# install-sysmon.ps1
# Downloads Sysmon + the SwiftOnSecurity configuration and installs it.
# Invoked by the CustomScriptExtension in main.tf.
# Reference script derived from the run-command used during the project.

$ErrorActionPreference = "Stop"
$tmp = Join-Path $env:TEMP "Sysmon"
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

Invoke-WebRequest "https://download.sysinternals.com/files/Sysmon.zip" `
    -OutFile (Join-Path $tmp "Sysmon.zip")
Expand-Archive (Join-Path $tmp "Sysmon.zip") -DestinationPath $tmp -Force

Invoke-WebRequest "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" `
    -OutFile (Join-Path $tmp "sysmonconfig.xml")

& (Join-Path $tmp "Sysmon64.exe") -accepteula -i (Join-Path $tmp "sysmonconfig.xml")
