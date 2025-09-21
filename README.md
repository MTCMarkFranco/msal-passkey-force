# 🔐 Secure Kiosk App with Entra ID Protection

A React Single Page Application (SPA) with enterprise-grade security featuring:
- **PKCE (Proof Key for Code Exchange)** - The strongest security for SPAs
- **Device Code Flow** - Perfect for kiosk scenarios where users can't enter passwords
- **Passkey Authentication** - Modern passwordless authentication via QR codes
- **Microsoft Entra ID Integration** - Enterprise identity protection
- **Hybrid Architecture** - Client + Server for maximum security

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Kiosk Browser │◄──►│   Node.js Server │◄──►│   Entra ID      │
│   (React SPA)   │    │   (Auth Proxy)   │    │   (OAuth 2.0)   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         │                       ▼                       │
         │              ┌─────────────────┐              │
         │              │   QR Code Gen   │              │
         │              │   Device Codes  │              │
         │              └─────────────────┘              │
         │                                               │
         └──────────────── Mobile Device ◄──────────────┘
                         (Passkey Auth)
```

## 🔒 Security Features

### **Why This Architecture is the Strongest**

1. **PKCE for SPAs** - Eliminates authorization code interception attacks
2. **Device Code Flow** - No passwords entered on kiosk (perfect for public terminals)
3. **Passkey Support** - Leverages WebAuthn through Entra ID
4. **Server-Side Session Management** - Protects tokens from client-side attacks
5. **Rate Limiting & Security Headers** - Prevents abuse and enhances security
6. **Secure Token Storage** - Tokens never exposed to browser storage

### **Authentication Flow**

```
1. User approaches kiosk
2. Clicks "Start Secure Sign-In"
3. Server generates device code + QR code
4. User scans QR with mobile device
5. Mobile device authenticates (passkey/biometrics)
6. Server receives auth confirmation
7. React app gets session token
8. User accesses secure kiosk functionality
```

## 🚀 Setup Instructions

### **1. Entra ID App Registration - Detailed Steps**

#### **Step 1: Create Entra ID App Registration**
1. Go to [Azure Portal](https://portal.azure.com)
2. Navigate to **Microsoft Entra ID** > **App registrations**
3. Click **New registration**
4. Create new registration with these settings:
   - **Name**: `Secure Kiosk App`
   - **Supported account types**: `Accounts in this organizational directory only (Single tenant)`
   - **Redirect URI**: Select `Public client/native (mobile & desktop)`
   - **URI**: `http://localhost:3001/auth/callback`
5. Click **Register**

#### **Step 2: Configure Authentication**
1. In your app registration, go to **Authentication** in the left menu
2. Under **Redirect URIs**, click **Add URI**
3. Add redirect URI: `https://login.microsoftonline.com/common/oauth2/nativeclient`
4. Under **Advanced settings**, enable **Allow public client flows**: `Yes`
5. Click **Save**

#### **Step 3: Add API Permissions**
1. Go to **API permissions** in the left menu
2. Click **Add a permission**
3. Select **Microsoft Graph**
4. Select **Delegated permissions**
5. Add these permissions:
   - **User.Read** (Delegated) - Sign in and read user profile
   - **Profile** (Delegated) - View users' basic profile
   - **OpenId** (Delegated) - Sign users in
6. Click **Add permissions**
7. (Optional) Click **Grant admin consent** if you have admin rights

#### **Step 4: Create Client Secret**
1. Go to **Certificates & secrets** in the left menu
2. Under **Client secrets**, click **New client secret**
3. Add description: `Secure Kiosk Server Secret`
4. Set expiration (recommended: 12-24 months)
5. Click **Add**
6. **IMPORTANT**: Copy the secret **Value** immediately (it won't be shown again)

#### **Step 5: Copy Configuration Values**
From your app registration **Overview** page, copy:
- **Application (client) ID**
- **Directory (tenant) ID**
- **Client secret value** (from step 4)

### **2. Environment Setup**

#### **Step 6: Update .env File**
1. Copy environment template:
   ```bash
   cp .env.example .env
   ```

2. Edit the `.env` file and update these values with your Entra ID configuration:
   ```bash
   # Replace these with your actual values from the app registration
   CLIENT_ID=your-application-client-id-from-step-5
   TENANT_ID=your-directory-tenant-id-from-step-5  
   CLIENT_SECRET=your-client-secret-value-from-step-4
   
   # These can stay as defaults for development
   PORT=3001
   NODE_ENV=development
   ALLOWED_ORIGINS=http://localhost:3000,http://localhost:3001
   # ... rest of the configuration
   ```

3. **Security Note**: Never commit the `.env` file to version control (it's already in `.gitignore`)

### **3. Install Dependencies**

```bash
npm install
```

### **4. Validate Setup**

Run the setup validation script to check your configuration:

```bash
npm run setup
```

This will verify:
- ✅ All required environment variables are configured
- ✅ MSAL configuration is valid
- ✅ Required port (3000) is available
- ✅ Dependencies are properly installed

If you see any errors, follow the detailed instructions provided by the script.

### **5. Development & Production**

The application now runs as a **consolidated single-server setup** on port 3000:

```bash
# For quick development (builds and starts)
npm run dev

# For development with hot-reload watching
npm run dev:watch

# For production
npm start
```

**Single Server Benefits:**
- ✅ **Simplified deployment** - One server, one port
- ✅ **No CORS issues** - Frontend and backend on same origin  
- ✅ **Better security** - No cross-origin requests
- ✅ **Azure-ready** - Perfect for App Service deployment

The server now serves:
- **React SPA** at `http://localhost:3000/`
- **API endpoints** at `http://localhost:3000/auth/*`
- **Health check** at `http://localhost:3000/health`

## 📱 How to Use

### **For End Users (Kiosk)**

1. **Approach the kiosk** - Screen shows sign-in required
2. **Click "Start Secure Sign-In"** - Initiates device code flow
3. **Scan QR code** with your mobile device
4. **Authenticate on mobile** using:
   - Face ID / Touch ID
   - Windows Hello
   - Hardware security keys
   - Passkeys
5. **Access granted** - Kiosk shows your secure dashboard

### **Mobile Authentication Options**

The QR code redirects to Entra ID which supports:
- **Passkeys** (WebAuthn)
- **Microsoft Authenticator** 
- **Biometric authentication**
- **Hardware security keys**
- **Phone sign-in**

## 🛡️ Security Best Practices Implemented

### **Authentication**
- ✅ OAuth 2.0 Authorization Code Flow with PKCE
- ✅ Device Code Flow for kiosks
- ✅ Passkey support via Entra ID
- ✅ Multi-factor authentication options
- ✅ Session timeout and refresh

### **Authorization**
- ✅ Least privilege access (User.Read only)
- ✅ Token scoping
- ✅ Secure session management
- ✅ Automatic logout on expiration

### **Transport Security**
- ✅ HTTPS required in production
- ✅ Secure headers (Helmet.js)
- ✅ CORS protection
- ✅ Rate limiting

### **Application Security**
- ✅ No credentials in client code
- ✅ Server-side token management
- ✅ Input validation
- ✅ Error handling without information leakage

## 🎯 Kiosk-Specific Features

### **Perfect for Public Terminals**
- No keyboard password entry required
- QR code authentication via personal devices
- Automatic session cleanup
- Tamper-resistant authentication flow

### **Enterprise Security**
- Centralized Entra ID management
- Conditional access policies supported
- Audit logging via Entra ID
- Device compliance checking

### **User Experience**
- Clear visual authentication progress
- Multiple authentication options
- Mobile-friendly QR codes
- Automatic session management

## 🏭 Production Considerations

### **Deployment**
```bash
# Set production environment variables
NODE_ENV=production
CLIENT_ID=prod-client-id
TENANT_ID=your-tenant-id
CLIENT_SECRET=secret-from-key-vault
```

### **Security Hardening**
- Store secrets in Azure Key Vault
- Enable Entra ID Conditional Access
- Configure network security groups
- Set up audit logging and monitoring

## 📚 Technologies Used

### **Frontend**
- React 18 with hooks
- Axios for API calls
- Modern CSS with responsive design
- Webpack 5 bundling

### **Backend**
- Node.js with Express
- MSAL Node for authentication
- QR code generation
- Security middleware (Helmet, CORS, Rate Limiting)

### **Security**
- Microsoft Entra ID (Azure AD)
- OAuth 2.0 with PKCE
- Device Code Flow
- Passkey/WebAuthn support

## License

MIT License