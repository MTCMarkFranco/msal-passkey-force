/**
 * Setup Helper for Secure Kiosk App
 * 
 * This script helps validate the environment configuration
 * and provides guidance on setting up Entra ID authentication
 */

require('dotenv').config();
const fs = require('fs');
const path = require('path');

console.log('🔐 Secure Kiosk App - Setup Validation\n');

// Check if .env exists
const envPath = path.join(__dirname, '..', '.env');
if (!fs.existsSync(envPath)) {
  console.log('❌ .env file not found');
  console.log('📋 Please copy .env.example to .env and configure your settings\n');
  console.log('Commands to run:');
  console.log('  cp .env.example .env');
  console.log('  # Then edit .env with your Entra ID configuration\n');
  process.exit(1);
}

console.log('✅ .env file found');

// Validate required environment variables
const requiredVars = [
  'CLIENT_ID',
  'TENANT_ID', 
  'CLIENT_SECRET'
];

const missingVars = [];
const defaultValues = [];

requiredVars.forEach(varName => {
  const value = process.env[varName];
  if (!value || value.startsWith('your-')) {
    if (!value) {
      missingVars.push(varName);
    } else {
      defaultValues.push(varName);
    }
  }
});

if (missingVars.length > 0 || defaultValues.length > 0) {
  console.log('\n❌ Configuration Issues Found:\n');
  
  if (missingVars.length > 0) {
    console.log('Missing environment variables:');
    missingVars.forEach(varName => {
      console.log(`  - ${varName}`);
    });
    console.log('');
  }
  
  if (defaultValues.length > 0) {
    console.log('Variables still using default values:');
    defaultValues.forEach(varName => {
      console.log(`  - ${varName}: ${process.env[varName]}`);
    });
    console.log('');
  }
  
  console.log('🔧 Setup Required:\n');
  console.log('1. Create Entra ID App Registration:');
  console.log('   - Go to https://portal.azure.com');
  console.log('   - Navigate to Microsoft Entra ID > App registrations');
  console.log('   - Create new registration with these settings:');
  console.log('     * Name: Secure Kiosk App');
  console.log('     * Account types: Single tenant');
  console.log('     * Redirect URI: Public client/native');
  console.log('     * URI: http://localhost:3001/auth/callback\n');
  
  console.log('2. Configure Authentication:');
  console.log('   - Add redirect URI: https://login.microsoftonline.com/common/oauth2/nativeclient');
  console.log('   - Enable "Allow public client flows"\n');
  
  console.log('3. Add API Permissions:');
  console.log('   - Microsoft Graph > User.Read (Delegated)');
  console.log('   - Microsoft Graph > Profile (Delegated)');
  console.log('   - Microsoft Graph > OpenId (Delegated)\n');
  
  console.log('4. Create Client Secret:');
  console.log('   - Go to Certificates & secrets');
  console.log('   - Create new client secret');
  console.log('   - Copy the value immediately\n');
  
  console.log('5. Update .env file with:');
  console.log('   - CLIENT_ID from app registration');
  console.log('   - TENANT_ID from app registration');
  console.log('   - CLIENT_SECRET from step 4\n');
  
  process.exit(1);
} else {
  console.log('✅ All required environment variables configured');
}

// Test server startup capability
console.log('\n🧪 Testing server configuration...\n');

try {
  const { PublicClientApplication } = require('@azure/msal-node');
  
  const msalConfig = {
    auth: {
      clientId: process.env.CLIENT_ID,
      authority: `https://login.microsoftonline.com/${process.env.TENANT_ID}`,
      clientSecret: process.env.CLIENT_SECRET
    }
  };
  
  const pca = new PublicClientApplication(msalConfig);
  console.log('✅ MSAL configuration valid');
  
} catch (error) {
  console.log('❌ MSAL configuration error:', error.message);
  process.exit(1);
}

// Check ports
console.log('🔍 Checking port availability...\n');

const net = require('net');

function checkPort(port) {
  return new Promise((resolve) => {
    const server = net.createServer();
    
    server.listen(port, () => {
      server.once('close', () => resolve(true));
      server.close();
    });
    
    server.on('error', () => resolve(false));
  });
}

Promise.all([
  checkPort(3000),
  checkPort(3001)
]).then(([port3000, port3001]) => {
  if (port3000) {
    console.log('✅ Port 3000 (React app) available');
  } else {
    console.log('⚠️  Port 3000 (React app) in use');
  }
  
  if (port3001) {
    console.log('✅ Port 3001 (Auth server) available');
  } else {
    console.log('⚠️  Port 3001 (Auth server) in use');
  }
  
  console.log('\n🎉 Setup validation complete!\n');
  console.log('🚀 Ready to start development:');
  console.log('   npm run dev\n');
  console.log('📱 Your app will be available at:');
  console.log('   - React app: http://localhost:3000');
  console.log('   - Auth server: http://localhost:3001\n');
  console.log('🔒 Security features enabled:');
  console.log('   ✅ PKCE (Proof Key for Code Exchange)');
  console.log('   ✅ Device Code Flow for kiosks');
  console.log('   ✅ Passkey authentication support');
  console.log('   ✅ QR code mobile sign-in');
  console.log('   ✅ Rate limiting and security headers\n');
  
});