# Kill any existing node processes
Write-Host "Stopping existing Node.js processes..."
Stop-Process -Name "node" -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 3

# Start the server
Write-Host "Starting server..."
Set-Location "c:\Projects\msal-passkey-force"
node server/index.js