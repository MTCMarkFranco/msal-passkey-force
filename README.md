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

### **1. Entra ID App Registration**

1. Go to [Azure Portal](https://portal.azure.com) → Microsoft Entra ID → App registrations
2. Create new registration:
   - **Name**: `Secure Kiosk App`
   - **Supported account types**: `Accounts in this organizational directory only`
   - **Redirect URI**: `Public client/native` → `http://localhost:3001/auth/callback`

3. **Authentication Settings**:
   - Add additional redirect URI: `https://login.microsoftonline.com/common/oauth2/nativeclient`
   - Enable **Allow public client flows**: Yes
   - Advanced settings → **Allow public client flows**: Yes

4. **API Permissions**:
   ```
   Microsoft Graph:
   - User.Read (Delegated)
   - Profile (Delegated) 
   - OpenId (Delegated)
   ```

5. **Certificates & Secrets**:
   - Create new client secret (for server-side flows)
   - Copy the secret value immediately

6. **Copy Configuration**:
   - Application (client) ID
   - Directory (tenant) ID
   - Client secret value

### **2. Environment Setup**

1. Copy environment template:
   ```bash
   cp .env.example .env
   ```

2. Update `.env` file with your Entra ID configuration

### **3. Install Dependencies**

```bash
npm install
```

### **4. Development Mode**

Run both client and server concurrently:

```bash
npm run dev
```

This starts:
- React app on `http://localhost:3000`
- Auth server on `http://localhost:3001`

### **5. Production Deployment**

```bash
# Build the application
npm run build

# Start production server
npm start
```

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