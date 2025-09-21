@description('Primary location for all resources')
param location string = resourceGroup().location

@description('Resource token for unique naming')
param resourceToken string

// Variables for resource names
var appServicePlanName = 'azasp${resourceToken}'
var webAppName = 'app-play-et-trivia-toronto-hub-dev'
var keyVaultName = 'azkv${resourceToken}'
var logAnalyticsName = 'azlaw${resourceToken}'
var applicationInsightsName = 'azai${resourceToken}'
var managedIdentityName = 'azmi${resourceToken}'

// User-Assigned Managed Identity (required by AZD rules)
resource managedIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: managedIdentityName
  location: location
}

// Log Analytics Workspace
resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: logAnalyticsName
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
    features: {
      searchVersion: 1
      legacy: 0
      enableLogAccessUsingOnlyResourcePermissions: true
    }
  }
}

// Application Insights
resource applicationInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: applicationInsightsName
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: logAnalytics.id
    IngestionMode: 'LogAnalytics'
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

// Key Vault
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: keyVaultName
  location: location
  properties: {
    enabledForDeployment: false
    enabledForTemplateDeployment: false
    enabledForDiskEncryption: false
    enableRbacAuthorization: false
    tenantId: tenant().tenantId
    sku: {
      name: 'standard'
      family: 'A'
    }
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: 'Allow'
    }
    accessPolicies: []
  }
}

// App Service Plan (Premium P1V2)
resource appServicePlan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: appServicePlanName
  location: location
  sku: {
    name: 'P1V2'
    tier: 'PremiumV2'
    size: 'P1V2'
    family: 'Pv2'
    capacity: 1
  }
  kind: 'app'
  properties: {
    reserved: false
  }
}

// Web App
resource webApp 'Microsoft.Web/sites@2023-12-01' = {
  name: webAppName
  location: location
  tags: {
    'azd-service-name': 'web'
  }
  kind: 'app'
  identity: {
    type: 'SystemAssigned, UserAssigned'
    userAssignedIdentities: {
      '${managedIdentity.id}': {}
    }
  }
  properties: {
    serverFarmId: appServicePlan.id
    httpsOnly: true
    siteConfig: {
      alwaysOn: true
      nodeVersion: '18-lts'
      appSettings: [
        {
          name: 'WEBSITE_NODE_DEFAULT_VERSION'
          value: '18.17.0'
        }
        {
          name: 'SCM_DO_BUILD_DURING_DEPLOYMENT'
          value: 'true'
        }
        {
          name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
          value: applicationInsights.properties.ConnectionString
        }
        {
          name: 'ApplicationInsightsAgent_EXTENSION_VERSION'
          value: '~3'
        }
        {
          name: 'PORT'
          value: '3001'
        }
        {
          name: 'NODE_ENV'
          value: 'production'
        }
        {
          name: 'ALLOWED_ORIGINS'
          value: 'https://${webAppName}.azurewebsites.net'
        }

      ]
      connectionStrings: []
      minTlsVersion: '1.2'
      ftpsState: 'FtpsOnly'
      http20Enabled: true
      remoteDebuggingEnabled: false
    }
  }
}

// Key Vault Access Policy for Web App
resource keyVaultAccessPolicy 'Microsoft.KeyVault/vaults/accessPolicies@2023-07-01' = {
  name: 'add'
  parent: keyVault
  properties: {
    accessPolicies: [
      {
        tenantId: tenant().tenantId
        objectId: webApp.identity.principalId
        permissions: {
          secrets: [
            'get'
            'list'
          ]
        }
      }
    ]
  }
}

// Outputs
output WEBAPP_URI string = 'https://${webApp.properties.defaultHostName}'
output WEBAPP_NAME string = webApp.name
output KEY_VAULT_NAME string = keyVault.name
output KEY_VAULT_URL string = keyVault.properties.vaultUri
output APPLICATION_INSIGHTS_CONNECTION_STRING string = applicationInsights.properties.ConnectionString
output MANAGED_IDENTITY_PRINCIPAL_ID string = managedIdentity.properties.principalId
