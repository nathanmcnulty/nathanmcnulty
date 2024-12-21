# Set variables
$storageAccountRoot = "https://<storageAccount>.blob.core.windows.net/<containerName>/$env:COMPUTERNAME"
$sasToken = "sp=c&st=2024-12-21T06:11:59Z&se=2024-12-21T14:11:59Z&spr=https&sv=2022-11-02&sr=c&sig=S7fT4CSFN9KlCL1Ki3nflsn3kdyixTqWIAAGaSQ%2BRfI%3D"
$filename = "$env:COMPUTERNAME-$(Get-Date -Format FileDateTime)"

# Ensure Defender staging folder exists
New-Item -Path $env:TEMP -Name Defender -ItemType Directory -Force -ErrorAction SilentlyContinue

# Copy MPLog files
Get-ChildItem -Path "$env:ProgramData\Microsoft\Windows Defender\Support\*.log" | Copy-Item -Destination "$env:TEMP\Defender\" -Force

# Create performance recording
New-MpPerformanceRecording -RecordTo "$env:TEMP\Defender\$filename.etl" -Seconds 3600

# Create compressed archive file
Compress-Archive -Path "$env:TEMP\Defender\" -DestinationPath "$env:TEMP\$filename.zip"

# Upload file to Azure blob storage
$headers = @{ "x-ms-blob-type" = "BlockBlob"; "x-ms-date" = "$(Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")"}
Invoke-RestMethod -Method "PUT" -Headers $headers -Uri "$storageAccountRoot/$filename.zip?$sasToken" -InFile "$env:TEMP\$filename.zip"

# Cleanup files
Remove-Item "$env:TEMP\$filename.zip" -Force
Remove-Item "$env:TEMP\Defender" -Recurse -Force