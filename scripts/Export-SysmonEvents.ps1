# Export Sysmon Operational events to normalized CSV for the SOC Lab.
# Run PowerShell as Administrator if access to the log is restricted.
param(
    [int]$MaxEvents = 5000,
    [string]$OutputPath = "$PSScriptRoot\..\data\sysmon_export.csv"
)
$logName = "Microsoft-Windows-Sysmon/Operational"
try {
    $events = Get-WinEvent -LogName $logName -MaxEvents $MaxEvents -ErrorAction Stop
} catch {
    Write-Error "Could not read $logName. Is Sysmon installed and is the log available? $($_.Exception.Message)"
    exit 1
}
$rows = foreach ($event in $events) {
    [xml]$xml = $event.ToXml()
    $row = [ordered]@{
        EventID = $event.Id
        UtcTime = $event.TimeCreated.ToUniversalTime().ToString("o")
        Computer = $event.MachineName
    }
    foreach ($data in $xml.Event.EventData.Data) {
        if ($data.Name) { $row[$data.Name] = [string]$data.'#text' }
    }
    [pscustomobject]$row
}
$parent = Split-Path -Parent $OutputPath
if (!(Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
$rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Write-Host "Exported $($rows.Count) Sysmon events to $OutputPath"
Write-Host "Review the export for sensitive host/user/command-line data before sharing."
