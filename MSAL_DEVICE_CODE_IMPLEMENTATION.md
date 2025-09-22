# MSAL Device Code Flow with Passkey Implementation

## Overview
This implementation uses the official Microsoft Authentication Library (MSAL) for Node.js to provide device code authentication with Passkey support for the target UPN: `dev@MngEnvMCAP490549.onmicrosoft.com`.

## Flow Description

### 1. User Initiates Authentication
- User clicks authentication button in React app
- React app calls `POST /auth/device-code/start`

### 2. Server Initiates MSAL Device Code Flow
- Server uses `@azure/msal-node` to call `pca.acquireTokenByDeviceCode()`
- MSAL automatically handles the device code request to Microsoft Entra ID
- Microsoft returns device code info including:
  - User code (6-digit code)
  - Verification URI 
  - Verification URI Complete (contains QR code from Entra ID)
  - Expiration time
  - Polling interval

### 3. QR Code Display
- Server returns the `verificationUriComplete` which contains Entra ID's native QR code
- No custom QR code generation needed - Microsoft provides the QR code URL
- React app displays this QR code for users to scan

### 4. User Authentication with Passkey
- User scans QR code with their mobile device
- Redirected to Microsoft login page for the specific tenant
- User authenticates using Passkey (if configured for the UPN)
- Microsoft handles the entire authentication flow

### 5. Polling for Completion
- React app polls `GET /auth/device-code/status/:sessionId`
- Server checks session status updated by MSAL background process
- When authentication completes, MSAL updates the session with tokens

### 6. Authentication Complete
- User is now authenticated in the React app
- Access tokens available for Microsoft Graph API calls
- Session includes user information and valid tokens

## Key Endpoints

### `POST /auth/device-code/start`
Initiates MSAL device code flow and returns:
```json
{
  "sessionId": "uuid",
  "userCode": "XXXXXXX",
  "verificationUri": "https://microsoft.com/devicelogin",
  "verificationUriComplete": "https://microsoft.com/devicelogin?otc=XXXXXXX", // Contains QR code
  "qrCodeUrl": "https://microsoft.com/devicelogin?otc=XXXXXXX", // Alias
  "message": "To sign in, use a web browser to open...",
  "expiresIn": 900,
  "interval": 5,
  "status": "pending"
}
```

### `GET /auth/device-code/status/:sessionId`
Returns current authentication status:
```json
{
  "status": "completed", // "pending", "completed", "failed", "expired"
  "sessionId": "uuid",
  "user": {
    "name": "Dev User",
    "username": "dev@MngEnvMCAP490549.onmicrosoft.com",
    "homeAccountId": "..."
  }
}
```

### `GET /auth/token/:sessionId`
Returns access token for API calls (when authenticated):
```json
{
  "accessToken": "eyJ...",
  "tokenType": "Bearer",
  "scopes": ["openid", "profile", "User.Read"],
  "expiresOn": "2025-09-21T..."
}
```

## Configuration Required

Ensure your `.env` file contains:
```
CLIENT_ID=your-azure-app-client-id
TENANT_ID=your-tenant-id-or-domain
DEFAULT_SCOPES=openid,profile,User.Read
```

## Target UPN Configuration
The implementation is specifically configured for:
- **UPN**: `dev@MngEnvMCAP490549.onmicrosoft.com`
- The server validates this UPN during authentication
- Passkey authentication must be configured for this user in Entra ID

## Passkey Setup Requirements
For passkey authentication to work:
1. The target UPN must have Passkey authentication enabled in Entra ID
2. The user must have registered a passkey with their Microsoft account
3. The Entra ID tenant must allow passkey authentication

## Benefits of MSAL Implementation
1. **Official Microsoft Library**: Uses the supported MSAL library
2. **Built-in QR Codes**: Entra ID provides QR codes automatically
3. **Passkey Support**: Native support for passkey authentication
4. **Proper Error Handling**: MSAL handles all OAuth error scenarios
5. **Token Management**: Automatic token validation and refresh capabilities
6. **Security**: Follows Microsoft's recommended authentication patterns

## Testing the Flow
1. Start the server: `npm run start`
2. Open browser to `http://localhost:3000`
3. Click "Authenticate" button
4. Scan the displayed QR code with mobile device
5. Authenticate with passkey as `dev@MngEnvMCAP490549.onmicrosoft.com`
6. React app will show authentication success