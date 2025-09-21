@echo off
setlocal enabledelayedexpansion

echo.
echo === Azure Deployment for MSAL Passkey Force App ===
echo.

REM Check if azd is installed
azd version >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Azure Developer CLI (azd) is not installed
    echo Please install from: https://learn.microsoft.com/en-us/azure/developer/azure-developer-cli/install-azd
    pause
    exit /b 1
)

REM Check if az is installed  
az version >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Azure CLI is not installed
    echo Please install from: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli
    pause
    exit /b 1
)

REM Set environment variables
set AZURE_ENV_NAME=dev
set AZURE_LOCATION=canadacentral

echo Environment: %AZURE_ENV_NAME%
echo Location: %AZURE_LOCATION%
echo.

REM Build the application
echo Building application...
call npm install
if %errorlevel% neq 0 (
    echo Error: Failed to install dependencies
    pause
    exit /b 1
)

call npm run build
if %errorlevel% neq 0 (
    echo Error: Failed to build application
    pause
    exit /b 1
)

echo.
echo Starting deployment to Azure...
echo This will create resources in: rg-rg-et-trivia-dev
echo App Service: app-play-et-trivia-toronto-hub-dev
echo.

REM Deploy with azd
azd up --environment %AZURE_ENV_NAME%

if %errorlevel% equ 0 (
    echo.
    echo === Deployment Successful! ===
    echo.
    echo Your application has been deployed to Azure.
    echo Check the output above for the application URL.
    echo.
    echo Next steps:
    echo 1. Configure your Entra ID application registration
    echo 2. Update Key Vault with your application secrets  
    echo 3. Test the authentication flow
    echo.
) else (
    echo.
    echo === Deployment Failed ===
    echo Please check the error messages above.
    echo.
)

pause