# Specify output directory and create if it does not exist
$outDir = 'C:\Temp'
if (!(Test-Path -Path $outDir)) { New-Item -Path $outDir -ItemType Directory -Force }

# Clean up previous export
if ((Test-Path -Path $outDir\export.csv) -or (Test-Path -Path $outDir\export.txt)) { Remove-Item -Path $outDir\export.* }

# Iterate through each DC and pull the debug logs
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).DomainControllers.name | ForEach-Object {
    Write-Output "Collecting logs from $_"
    $path = "\\$_\admin$\debug\netlogon.log"
    if (Test-Path $path) {
        Add-Content -Path "$outDir\export.txt" -Value (Get-Content $path) -Verbose
    }
}

# Filter, sort, and output CSV
Import-Csv "$outDir\export.txt" -Delimiter ' ' -Header Date,Time,Event,Domain,Error,Name,IPAddress | Select-Object Date, Time, Name, IPAddress | Sort-Object IPAddress -Unique | Export-Csv "$outDir\export.csv"