# Entra ID Passkey Integration Setup Guide

## Overview
This guide will help you set up Microsoft Entra ID integration with WebAuthn passkeys for the tenant `MngEnvMCAP490549.onmicrosoft.com`.

## Prerequisites
- Admin access to MngEnvMCAP490549.onmicrosoft.com tenant
- Azure Portal access
- Node.js application deployed and accessible

## Step 1: Create Azure App Registration

### 1.1 Navigate to Azure Portal
1. Go to [Azure Portal](https://portal.azure.com)
2. Sign in with admin account for MngEnvMCAP490549.onmicrosoft.com
3. Navigate to **Microsoft Entra ID** > **App registrations**

### 1.2 Create New Registration
1. Click **New registration**
2. Fill in the details:
   - **Name**: `Secure Kiosk Passkey App`
   - **Supported account types**: `Accounts in this organizational directory only (MngEnvMCAP490549.onmicrosoft.com only)`
   - **Redirect URI**: 
     - Platform: `Web`
     - URL: `http://localhost:3000/auth/callback` (for development)
     - For production: `https://your-domain.com/auth/callback`

### 1.3 Note Important Values
After creation, note these values:
- **Application (client) ID**: Copy this for ENTRA_CLIENT_ID
- **Directory (tenant) ID**: Should be `MngEnvMCAP490549.onmicrosoft.com`

## Step 2: Configure App Registration

### 2.1 Create Client Secret
1. In your app registration, go to **Certificates & secrets**
2. Click **New client secret**
3. Add description: `Passkey App Secret`
4. Set expiration: `24 months` (recommended)
5. Click **Add**
6. **Important**: Copy the secret value immediately (for ENTRA_CLIENT_SECRET)

### 2.2 Configure API Permissions
1. Go to **API permissions**
2. Click **Add a permission**
3. Select **Microsoft Graph**
4. Choose **Delegated permissions**
5. Add these permissions:
   - `User.Read` (to read user profile)
   - `User.ReadBasic.All` (to read basic user info)
6. Click **Add permissions**
7. Click **Grant admin consent** (admin required)

### 2.3 Configure Authentication
1. Go to **Authentication**
2. Add additional redirect URIs if needed:
   - `http://localhost:3000` (for development)
   - Your production domain
3. Under **Implicit grant and hybrid flows**:
   - Check ✅ **Access tokens**
   - Check ✅ **ID tokens**
4. Save changes

## Step 3: Environment Configuration

### 3.1 Create .env file
Create a `.env` file in your project root:

```bash
# Server Configuration
PORT=3000
NODE_ENV=development
SESSION_SECRET=generate-a-secure-random-string-here

# Microsoft Entra ID Configuration
ENTRA_CLIENT_ID=your-application-client-id-here
ENTRA_CLIENT_SECRET=your-client-secret-here
ENTRA_TENANT_ID=MngEnvMCAP490549.onmicrosoft.com

# WebAuthn Configuration
RP_ID=localhost
RP_NAME=Secure Kiosk App - Enterprise Edition
ORIGIN=http://localhost:3000
```

### 3.2 Generate Secure Session Secret
```bash
# Run this command to generate a secure session secret:
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

## Step 4: Install and Configure MSAL (Optional - for production)

For a full production implementation, install Microsoft Authentication Library:

```bash
npm install @azure/msal-browser @azure/msal-node
```

### 4.1 Frontend MSAL Configuration (Production)
```javascript
import { PublicClientApplication } from "@azure/msal-browser";

const msalConfig = {
  auth: {
    clientId: "your-client-id",
    authority: "https://login.microsoftonline.com/MngEnvMCAP490549.onmicrosoft.com"
  }
};

const msalInstance = new PublicClientApplication(msalConfig);
```

## Step 5: Security Considerations

### 5.1 Production Security
- Use HTTPS in production
- Store secrets in Azure Key Vault
- Enable Conditional Access policies
- Implement proper token validation
- Use managed identities when possible

### 5.2 Passkey Security
- Require user verification for enterprise users
- Use platform authenticators when available
- Implement attestation validation
- Store encrypted metadata locally
- Regular security audits

## Step 6: Testing the Integration

### 6.1 Start the Application
```bash
npm run server:dev
```

### 6.2 Test Flow
1. Navigate to `http://localhost:3000`
2. Choose "Enterprise Authentication"
3. Enter a test user: `testuser@MngEnvMCAP490549.onmicrosoft.com`
4. Complete Entra ID authentication (simulated in demo)
5. Register a passkey
6. Test authentication with the passkey

## Step 7: Deployment Considerations

### 7.1 Production Environment Variables
```bash
# Production .env
NODE_ENV=production
HTTPS=true
ORIGIN=https://your-production-domain.com
RP_ID=your-production-domain.com
SESSION_SECRET=use-azure-key-vault-reference
ENTRA_CLIENT_SECRET=use-azure-key-vault-reference
```

### 7.2 Azure Deployment
- Use Azure App Service or Azure Container Instances
- Configure managed identity
- Use Azure Key Vault for secrets
- Enable Application Insights for monitoring

## Troubleshooting

### Common Issues
1. **CORS Errors**: Ensure redirect URI matches exactly
2. **Token Validation Fails**: Check tenant ID and client ID
3. **Passkey Registration Fails**: Verify WebAuthn support
4. **Session Issues**: Check session secret and cookie settings

### Debug Mode
Set `LOG_LEVEL=debug` in your environment to see detailed logs.

## Security Best Practices

1. **Never commit secrets** to version control
2. **Use HTTPS** in production
3. **Implement proper CORS** policies
4. **Validate all tokens** server-side
5. **Use least privilege** for permissions
6. **Enable audit logging** for all authentication events
7. **Regular security reviews** and updates

## Support
For issues with this implementation:
1. Check the browser console for WebAuthn errors
2. Review server logs for authentication issues
3. Verify Azure App Registration configuration
4. Test with different browsers and devices