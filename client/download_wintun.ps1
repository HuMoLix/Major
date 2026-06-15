$wintun_version = "0.14.1"
$url = "https://www.wintun.net/builds/wintun-$wintun_version.zip"
$zip_path = Join-Path $PSScriptRoot "wintun.zip"
$extract_dir = Join-Path $PSScriptRoot "wintun_extracted"

Write-Host "Downloading Wintun $wintun_version from $url..."
Invoke-WebRequest -Uri $url -OutFile $zip_path

Write-Host "Extracting archive..."
Expand-Archive -Path $zip_path -DestinationPath $extract_dir -Force

# Copy wintun.dll from bin/amd64/ to the client root and target directories
$dll_source = Join-Path $extract_dir "wintun\bin\amd64\wintun.dll"
$dest_root = Join-Path $PSScriptRoot "wintun.dll"
$dest_target_debug = Join-Path $PSScriptRoot "target\debug\wintun.dll"
$dest_target_release = Join-Path $PSScriptRoot "target\release\wintun.dll"

Write-Host "Copying wintun.dll to workspace..."
Copy-Item -Path $dll_source -Destination $dest_root -Force

# Create target directories if they don't exist
New-Item -ItemType Directory -Force -Path (Join-Path $PSScriptRoot "target\debug") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $PSScriptRoot "target\release") | Out-Null

Copy-Item -Path $dll_source -Destination $dest_target_debug -Force
Copy-Item -Path $dll_source -Destination $dest_target_release -Force

# Cleanup
Remove-Item -Path $zip_path -Force
Remove-Item -Path $extract_dir -Recurse -Force

Write-Host "Wintun DLL setup completed successfully!"
