targetScope = 'subscription'

@minLength(1)
@maxLength(64)
@description('Name of the environment that can be used as part of naming resource convention')
param environmentName string

@minLength(1)
@description('Primary location for all resources')
param location string

@description('Name of the resource group')
param resourceGroupName string = 'rg-${environmentName}'

// Generate unique resource token for naming
var resourceToken = uniqueString(subscription().id, location, environmentName)

// Create resource group
resource rg 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: resourceGroupName
  location: location
  tags: {
    'azd-env-name': environmentName
  }
}

// Deploy main resources within the resource group
module resources './main-resources.bicep' = {
  scope: rg
  params: {
    location: location
    resourceToken: resourceToken
  }
}

// Outputs
output RESOURCE_GROUP_ID string = rg.id
output AZURE_LOCATION string = location
output AZURE_TENANT_ID string = tenant().tenantId
output WEBAPP_URI string = resources.outputs.WEBAPP_URI
output WEBAPP_NAME string = resources.outputs.WEBAPP_NAME
output KEY_VAULT_NAME string = resources.outputs.KEY_VAULT_NAME
