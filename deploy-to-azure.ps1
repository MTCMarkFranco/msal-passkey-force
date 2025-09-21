#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Deploy the MSAL Passkey Force application to Azure App Service Premium

.DESCRIPTION
    This script deploys the secure kiosk authentication application to Azure App Service
    using Azure Developer CLI (azd). It provisions all necessary Azure resources including
    App Service, Key Vault, Application Insights, and Log Analytics.

.PARAMETER EnvironmentName
    The environment name for the deployment (defaults to "dev")

.PARAMETER Location
    The Azure region for deployment (defaults to "westus2")

.PARAMETER ResourceGroup
    The target resource group name (defaults to "rg-rg-et-trivia-dev")

.PARAMETER Preview
    Run in preview mode to show what will be deployed without making changes

.EXAMPLE
    .\deploy-to-azure.ps1
    Deploys with default settings

.EXAMPLE
    .\deploy-to-azure.ps1 -Preview
    Shows what will be deployed without making changes

.EXAMPLE
    .\deploy-to-azure.ps1 -EnvironmentName "prod" -Location "westus2"
    Deploys to production environment in East US
#>

param(
    [string]$EnvironmentName = "dev",
    [string]$Location = "westus2",  # Must be westus2 to match existing resource group
    [string]$ResourceGroup = "rg-rg-et-trivia-dev",  # Existing resource group in westus2
    [switch]$Preview
)

# Set error action preference
$ErrorActionPreference = "Stop"

function Write-Header {
    param([string]$Message)
    Write-Host "`n=== $Message ===" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "✅ $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "⚠️  $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "❌ $Message" -ForegroundColor Red
}

try {
    Write-Header "Azure Deployment Script for MSAL Passkey Force App"
    
    # Check prerequisites
    Write-Header "Checking Prerequisites"
    
    # Check Azure CLI
    try {
        $azVersion = az version --output json | ConvertFrom-Json
        Write-Success "Azure CLI version $($azVersion.'azure-cli') is installed"
    }
    catch {
        Write-Error "Azure CLI is not installed or not in PATH"
        Write-Host "Please install Azure CLI from: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
        exit 1
    }
    
    # Check Azure Developer CLI
    try {
        $azdVersion = azd version --output json | ConvertFrom-Json
        Write-Success "Azure Developer CLI version $($azdVersion.azd.version) is installed"
    }
    catch {
        Write-Error "Azure Developer CLI (azd) is not installed or not in PATH"
        Write-Host "Please install azd from: https://learn.microsoft.com/en-us/azure/developer/azure-developer-cli/install-azd"
        exit 1
    }
    
    # Check if logged into Azure
    Write-Header "Checking Azure Authentication"
    try {
        $account = az account show --output json | ConvertFrom-Json
        Write-Success "Logged into Azure as: $($account.user.name)"
        Write-Host "Subscription: $($account.name) ($($account.id))" -ForegroundColor Gray
    }
    catch {
        Write-Warning "Not logged into Azure. Attempting login..."
        az login
        $account = az account show --output json | ConvertFrom-Json
        Write-Success "Successfully logged into Azure as: $($account.user.name)"
    }
    
    # Validate location for existing resource group
    if ($ResourceGroup -eq "rg-rg-et-trivia-dev" -and $Location -ne "westus2") {
        Write-Error "The resource group '$ResourceGroup' exists in 'westus2'. Please use -Location 'westus2' or choose a different resource group name."
        exit 1
    }
    
    # Set environment variables
    Write-Header "Setting Environment Variables"
    $env:AZURE_ENV_NAME = $EnvironmentName
    $env:AZURE_LOCATION = $Location
    
    Write-Host "Environment Name: $EnvironmentName" -ForegroundColor Gray
    Write-Host "Location: $Location" -ForegroundColor Gray
    Write-Host "Resource Group: $ResourceGroup" -ForegroundColor Gray
    
    # Initialize azd if needed
    Write-Header "Initializing Azure Developer CLI"
    if (-not (Test-Path ".azure")) {
        Write-Host "Initializing azd environment..."
        azd init --environment $EnvironmentName --location $Location
        Write-Success "AZD environment initialized"
    } else {
        Write-Success "AZD environment already exists"
    }
    
    # Refresh azd environment to sync with Azure
    Write-Header "Refreshing Azure Developer CLI Environment"
    Write-Host "Synchronizing local environment with Azure deployment state..."
    try {
        azd env refresh
        Write-Success "AZD environment refreshed and synchronized with Azure"
    }
    catch {
        Write-Warning "Could not refresh azd environment. This may be normal for new deployments."
        Write-Host "Continuing with deployment..."
    }
    
    # Build the application
    Write-Header "Building Application"
    Write-Host "Installing dependencies..."
    npm install
    Write-Success "Dependencies installed"
    
    Write-Host "Building application..."
    npm run build
    Write-Success "Application built successfully"
    
    if ($Preview) {
        # Preview deployment
        Write-Header "Previewing Azure Deployment"
        Write-Warning "Running in preview mode - no resources will be created"
        azd provision --preview
    } else {
        # Deploy to Azure
        Write-Header "Deploying to Azure"
        Write-Host "Provisioning Azure resources and deploying application..."
        azd up --environment $EnvironmentName
        
        # Check deployment status
        Write-Header "Deployment Summary"
        $outputs = azd env get-values --output json | ConvertFrom-Json
        
        if ($outputs.WEBAPP_URI) {
            Write-Success "Application deployed successfully!"
            Write-Host "`nDeployment Details:" -ForegroundColor Cyan
            Write-Host "  Web App URL: $($outputs.WEBAPP_URI)" -ForegroundColor Green
            Write-Host "  Web App Name: $($outputs.WEBAPP_NAME)" -ForegroundColor Gray
            Write-Host "  Resource Group: $ResourceGroup" -ForegroundColor Gray
            Write-Host "  Key Vault: $($outputs.KEY_VAULT_NAME)" -ForegroundColor Gray
            
            Write-Host "`n🚀 Your application is now live!" -ForegroundColor Green
            Write-Host "Visit: $($outputs.WEBAPP_URI)" -ForegroundColor Cyan
        } else {
            Write-Warning "Deployment completed but output values not available"
            Write-Host "Check the Azure portal for deployment status"
        }
    }
    
    Write-Header "Next Steps"
    Write-Host "1. Configure your Entra ID application registration" -ForegroundColor Yellow
    Write-Host "2. Update Key Vault with your application secrets" -ForegroundColor Yellow
    Write-Host "3. Test the authentication flow" -ForegroundColor Yellow
    Write-Host "4. Configure custom domains if needed" -ForegroundColor Yellow
    
} catch {
    Write-Error "Deployment failed: $($_.Exception.Message)"
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
    exit 1
}

Write-Success "Deployment script completed successfully!"