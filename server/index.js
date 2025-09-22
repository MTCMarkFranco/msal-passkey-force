const express = require('express');
const session = require('express-session');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const base64url = require('base64url');
const { ConfidentialClientApplication } = require('@azure/msal-node');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Entra ID Configuration - using your existing environment variables
const ENTRA_CONFIG = {
  clientId: process.env.CLIENT_ID || process.env.ENTRA_CLIENT_ID || '00000000-0000-0000-0000-000000000000',
  clientSecret: process.env.CLIENT_SECRET || process.env.ENTRA_CLIENT_SECRET,
  authority: `https://login.microsoftonline.com/${process.env.TENANT_ID || process.env.ENTRA_TENANT_ID || 'MngEnvMCAP490549.onmicrosoft.com'}`,
  tenantId: process.env.TENANT_ID || process.env.ENTRA_TENANT_ID || 'MngEnvMCAP490549.onmicrosoft.com',
  scopes: ['https://graph.microsoft.com/User.Read', 'https://graph.microsoft.com/User.ReadBasic.All']
};

// Initialize MSAL instance for server-side validation (only if properly configured)
let msalInstance = null;
if (ENTRA_CONFIG.clientId && ENTRA_CONFIG.clientSecret && 
    ENTRA_CONFIG.clientId !== '00000000-0000-0000-0000-000000000000') {
  try {
    msalInstance = new ConfidentialClientApplication({
      auth: {
        clientId: ENTRA_CONFIG.clientId,
        clientSecret: ENTRA_CONFIG.clientSecret,
        authority: ENTRA_CONFIG.authority,
      }
    });
    console.log('✅ MSAL configured successfully for tenant:', ENTRA_CONFIG.tenantId);
  } catch (error) {
    console.warn('⚠️ MSAL initialization failed:', error.message);
    console.warn('Entra ID features will be disabled');
  }
} else {
  console.warn('⚠️ Entra ID not fully configured - missing CLIENT_ID or CLIENT_SECRET');
  console.warn('Standalone passkey mode available only');
}

// Storage file paths
const USERS_FILE = path.join(__dirname, 'users.json');
const SESSIONS_FILE = path.join(__dirname, 'sessions.json');
const PASSKEY_REGISTRY_FILE = path.join(__dirname, 'passkey-registry.json');
const CRYPTO_KEYS_FILE = path.join(__dirname, 'crypto-keys.json');

// Cryptographic key management for passkey operations
function generateOrLoadCryptoKeys() {
  try {
    if (fs.existsSync(CRYPTO_KEYS_FILE)) {
      const keys = JSON.parse(fs.readFileSync(CRYPTO_KEYS_FILE, 'utf8'));
      console.log('Loaded existing cryptographic keys');
      return keys;
    }
  } catch (error) {
    console.error('Error loading crypto keys:', error);
  }

  // Generate new keys if none exist
  const keys = {
    serverKeyPair: {
      publicKey: crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
      }).publicKey,
      privateKey: crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
      }).privateKey
    },
    encryptionKey: crypto.randomBytes(32).toString('hex'), // AES-256 key for data encryption
    signingKey: crypto.randomBytes(64).toString('hex'),    // HMAC signing key
    createdAt: new Date().toISOString()
  };

  // Save keys securely
  fs.writeFileSync(CRYPTO_KEYS_FILE, JSON.stringify(keys, null, 2));
  fs.chmodSync(CRYPTO_KEYS_FILE, 0o600); // Read/write for owner only
  console.log('Generated new cryptographic keys');
  return keys;
}

// Load passkey registry for Entra ID user mappings
function loadPasskeyRegistry() {
  try {
    if (fs.existsSync(PASSKEY_REGISTRY_FILE)) {
      const data = JSON.parse(fs.readFileSync(PASSKEY_REGISTRY_FILE, 'utf8'));
      const registry = new Map(data);
      console.log(`Loaded ${registry.size} passkey registrations`);
      return registry;
    }
  } catch (error) {
    console.error('Error loading passkey registry:', error);
  }
  return new Map();
}

function savePasskeyRegistry(registry) {
  try {
    const data = Array.from(registry.entries());
    fs.writeFileSync(PASSKEY_REGISTRY_FILE, JSON.stringify(data, null, 2));
    console.log(`Saved ${registry.size} passkey registrations`);
  } catch (error) {
    console.error('Error saving passkey registry:', error);
  }
}

// Enhanced user loading with Entra ID integration
function loadUsers() {
  try {
    if (fs.existsSync(USERS_FILE)) {
      const data = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
      const users = new Map();
      for (const [key, value] of data) {
        // Convert userIdBuffer back to Buffer if it exists
        if (value.userIdBuffer && value.userIdBuffer.data) {
          value.userIdBuffer = Buffer.from(value.userIdBuffer.data);
        }
        // Convert credentialID back to Buffer for each authenticator and validate
        if (value.authenticators) {
          value.authenticators = value.authenticators.filter(auth => {
            try {
              if (auth.credentialID && auth.credentialID.data) {
                auth.credentialID = Buffer.from(auth.credentialID.data);
              }
              if (auth.credentialPublicKey && auth.credentialPublicKey.data) {
                auth.credentialPublicKey = Buffer.from(auth.credentialPublicKey.data);
              }
              // Validate that we have valid credential data
              return auth.credentialID && Buffer.isBuffer(auth.credentialID) && auth.credentialID.length > 0;
            } catch (error) {
              console.warn('Removing invalid authenticator:', error.message);
              return false;
            }
          });
        }
        users.set(key, value);
      }
      console.log(`Loaded ${users.size} users from file`);
      return users;
    }
  } catch (error) {
    console.error('Error loading users:', error);
  }
  return new Map();
}

function saveUsers(users) {
  try {
    const data = Array.from(users.entries());
    fs.writeFileSync(USERS_FILE, JSON.stringify(data, null, 2));
    console.log(`Saved ${users.size} users to file`);
  } catch (error) {
    console.error('Error saving users:', error);
  }
}

function loadSessions() {
  try {
    if (fs.existsSync(SESSIONS_FILE)) {
      const data = JSON.parse(fs.readFileSync(SESSIONS_FILE, 'utf8'));
      const sessions = new Map(data);
      console.log(`Loaded ${sessions.size} sessions from file`);
      return sessions;
    }
  } catch (error) {
    console.error('Error loading sessions:', error);
  }
  return new Map();
}

function saveSessions(sessions) {
  try {
    const data = Array.from(sessions.entries());
    fs.writeFileSync(SESSIONS_FILE, JSON.stringify(data, null, 2));
  } catch (error) {
    console.error('Error saving sessions:', error);
  }
}

// Initialize cryptographic keys and storage
const cryptoKeys = generateOrLoadCryptoKeys();
const passkeyRegistry = loadPasskeyRegistry(); // Maps Entra ID users to passkeys
const users = loadUsers();
const userSessions = loadSessions();

// Utility functions for data encryption (for sensitive local storage)
function encryptData(data) {
  const cipher = crypto.createCipher('aes-256-cbc', cryptoKeys.encryptionKey);
  let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

function decryptData(encryptedData) {
  try {
    const decipher = crypto.createDecipher('aes-256-cbc', cryptoKeys.encryptionKey);
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return JSON.parse(decrypted);
  } catch (error) {
    console.error('Decryption error:', error);
    return null;
  }
}

// Enhanced Entra ID user validation
async function validateEntraIdUser(accessToken) {
  if (!msalInstance) {
    throw new Error('Entra ID not configured - MSAL instance unavailable');
  }

  try {
    // In a real implementation, you would validate the token with Microsoft Graph
    // For now, we'll simulate this validation
    console.log('Validating Entra ID access token...');
    
    // Decode token to get user info (simplified - use proper JWT validation in production)
    const tokenParts = accessToken.split('.');
    if (tokenParts.length !== 3) {
      throw new Error('Invalid token format');
    }
    
    // This is a placeholder - implement proper JWT validation
    const payload = JSON.parse(Buffer.from(tokenParts[1], 'base64').toString());
    
    // Validate that the token is for our tenant
    if (payload.tid && payload.tid !== ENTRA_CONFIG.tenantId && 
        !payload.upn?.endsWith('@MngEnvMCAP490549.onmicrosoft.com')) {
      throw new Error('Token not for authorized tenant');
    }
    
    return {
      userId: payload.sub || payload.oid,
      userPrincipalName: payload.upn || payload.preferred_username,
      displayName: payload.name,
      email: payload.email || payload.upn,
      tenantId: payload.tid
    };
  } catch (error) {
    console.error('Entra ID validation error:', error);
    throw new Error('Invalid Entra ID token');
  }
}

// WebAuthn configuration
const rpID = process.env.RP_ID || 'localhost';
const rpName = process.env.RP_NAME || 'Secure Kiosk App';
const origin = process.env.ORIGIN || `http://localhost:${PORT}`;

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
});

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
}));

app.use(limiter);
app.use(cors({
  origin: origin,
  credentials: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Serve static files from the dist directory
app.use(express.static(path.join(__dirname, '../dist')));

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    entraIdConfigured: !!ENTRA_CONFIG.clientId && ENTRA_CONFIG.clientId !== '00000000-0000-0000-0000-000000000000',
    passkeyRegistrations: passkeyRegistry.size,
    totalUsers: users.size
  });
});

// Entra ID Integration Endpoints

/**
 * Get Entra ID configuration for frontend
 */
app.get('/api/auth/entra-config', (req, res) => {
  res.json({
    clientId: ENTRA_CONFIG.clientId,
    authority: ENTRA_CONFIG.authority,
    tenantId: ENTRA_CONFIG.tenantId,
    scopes: ENTRA_CONFIG.scopes,
    redirectUri: `${origin}/auth/callback`
  });
});

/**
 * Validate Entra ID token and prepare for passkey registration
 */
app.post('/api/auth/entra-validate', async (req, res) => {
  try {
    const { accessToken } = req.body;
    
    if (!accessToken) {
      return res.status(400).json({ error: 'Access token is required' });
    }

    // Validate the Entra ID token
    const entraUser = await validateEntraIdUser(accessToken);
    
    console.log('Validated Entra ID user:', {
      userPrincipalName: entraUser.userPrincipalName,
      displayName: entraUser.displayName,
      userId: entraUser.userId
    });

    // Store validated Entra ID info in session for passkey registration
    req.session.entraUser = entraUser;
    req.session.entraToken = accessToken;
    
    // Check if user already has passkeys registered
    const existingPasskeys = passkeyRegistry.get(entraUser.userPrincipalName) || [];
    
    res.json({
      validated: true,
      user: {
        userPrincipalName: entraUser.userPrincipalName,
        displayName: entraUser.displayName,
        email: entraUser.email
      },
      hasPasskeys: existingPasskeys.length > 0,
      passkeyCount: existingPasskeys.length
    });
  } catch (error) {
    console.error('Entra ID validation error:', error);
    res.status(401).json({ error: 'Invalid Entra ID token', details: error.message });
  }
});

// WebAuthn Registration Endpoints

/**
 * Generate registration options for a new passkey (Enhanced with Entra ID)
 */
app.post('/api/webauthn/generate-registration-options', async (req, res) => {
  try {
    const { username, displayName, useEntraId = false } = req.body;
    console.log('Registration request:', { username, displayName, useEntraId });

    // Enhanced validation for Entra ID users
    if (useEntraId) {
      if (!req.session.entraUser) {
        return res.status(401).json({ 
          error: 'Entra ID authentication required. Please authenticate with Entra ID first.' 
        });
      }
      
      // Use Entra ID user info
      const entraUser = req.session.entraUser;
      const effectiveUsername = entraUser.userPrincipalName;
      const effectiveDisplayName = entraUser.displayName;
      
      console.log('Using Entra ID user for passkey registration:', {
        userPrincipalName: effectiveUsername,
        displayName: effectiveDisplayName
      });
    } else {
      if (!username) {
        return res.status(400).json({ error: 'Username is required' });
      }
    }

    const finalUsername = useEntraId ? req.session.entraUser.userPrincipalName : username;
    const finalDisplayName = useEntraId ? req.session.entraUser.displayName : (displayName || username);

    // Create or get user
    let user = users.get(finalUsername);
    let needsUserIdUpdate = false;
    
    // Check if existing user has an invalid (too long) user ID
    if (user && user.userIdBuffer && user.userIdBuffer.length > 64) {
      console.log(`Existing user has invalid user ID length (${user.userIdBuffer.length}). Regenerating...`);
      needsUserIdUpdate = true;
    }
    
    if (!user || needsUserIdUpdate) {
      const userId = uuidv4();
      // Create a secure userHandle for Entra ID users (max 64 characters for WebAuthn)
      let userHandleString;
      if (useEntraId && req.session.entraUser && req.session.entraUser.userId) {
        // For Entra ID users, create a deterministic short handle from the user ID
        const crypto = require('crypto');
        const entraUserId = req.session.entraUser.userId.toString();
        // Create a short hash of the Entra ID to ensure uniqueness and stay under 64 chars
        const hash = crypto.createHash('sha256').update(entraUserId).digest('hex').slice(0, 20);
        userHandleString = `ent_${hash}`;
      } else {
        // For regular users, use a truncated UUID (remove dashes to save space)
        userHandleString = userId.replace(/-/g, '').slice(0, 32);
      }
      
      // Ensure user ID is within WebAuthn limits (1-64 characters)
      if (userHandleString.length === 0 || userHandleString.length > 64) {
        console.error('Invalid user handle generated:', {
          userHandleString,
          length: userHandleString.length,
          useEntraId,
          entraUserId: req.session.entraUser?.userId
        });
        throw new Error(`Invalid user ID length: ${userHandleString.length}. Must be 1-64 characters.`);
      }
      
      const userIdBuffer = Buffer.from(userHandleString, 'utf-8');
      
      console.log('Generated user handle:', {
        userHandleString,
        length: userHandleString.length,
        bufferLength: userIdBuffer.length,
        useEntraId,
        withinLimits: userIdBuffer.length <= 64
      });
      
      // Double-check that the buffer is within WebAuthn limits
      if (userIdBuffer.length > 64) {
        throw new Error(`User ID buffer too long: ${userIdBuffer.length} bytes. WebAuthn limit is 64 bytes.`);
      }
      
      user = {
        id: userId,
        userIdBuffer: userIdBuffer,
        userHandleString: userHandleString,
        username: finalUsername,
        displayName: finalDisplayName,
        authenticators: [],
        entraId: useEntraId ? {
          userId: req.session.entraUser.userId,
          userPrincipalName: req.session.entraUser.userPrincipalName,
          tenantId: req.session.entraUser.tenantId,
          registeredAt: new Date().toISOString()
        } : null,
        createdAt: new Date().toISOString()
      };
      
      users.set(finalUsername, user);
      saveUsers(users); // Persist to file
      
      console.log('Created new user:', { 
        id: user.id, 
        username: user.username, 
        userHandle: userHandleString,
        entraId: !!user.entraId 
      });
    } else {
      console.log('Found existing user:', { id: user.id, username: user.username });
    }

    console.log('User ID buffer type:', typeof user.userIdBuffer);
    console.log('User ID buffer constructor:', user.userIdBuffer.constructor.name);
    console.log('User ID buffer length:', user.userIdBuffer.length);

    // Enhanced security options for Entra ID users
    const isEntraIdUser = !!user.entraId;
    const options = await generateRegistrationOptions({
      rpName: `${rpName}${isEntraIdUser ? ' (Enterprise)' : ''}`,
      rpID,
      userID: user.userIdBuffer,
      userName: user.username,
      userDisplayName: user.displayName,
      attestationType: isEntraIdUser ? 'direct' : 'none', // Enhanced attestation for enterprise users
      excludeCredentials: user.authenticators
        .filter(authenticator => {
          // Filter out authenticators with invalid credentialIDs
          return authenticator.credentialID && 
                 (Buffer.isBuffer(authenticator.credentialID) || 
                  (typeof authenticator.credentialID === 'string' && authenticator.credentialID.length > 0));
        })
        .map(authenticator => ({
          id: authenticator.credentialID,
          type: 'public-key',
          transports: authenticator.transports || ['internal', 'hybrid'],
        })),
      authenticatorSelection: {
        authenticatorAttachment: isEntraIdUser ? 'platform' : 'cross-platform', // Prefer platform auth for enterprise
        userVerification: isEntraIdUser ? 'required' : 'preferred', // Require verification for enterprise
        residentKey: 'required', // Always require resident keys for better security
        requireResidentKey: true
      },
      supportedAlgorithmIDs: [-7, -257, -37, -38, -39], // Extended algorithm support
      extensions: {
        // Enhanced security extensions for enterprise users
        credProps: true,
        ...(isEntraIdUser && { 
          uvm: true, // User Verification Methods
          credentialHints: ['client-device', 'hybrid'] 
        })
      }
    });

    console.log('Generated registration options successfully', {
      enterprise: isEntraIdUser,
      userVerification: options.authenticatorSelection?.userVerification,
      residentKey: options.authenticatorSelection?.residentKey
    });

    // Store challenge and user info in session with enhanced metadata
    req.session.currentChallenge = options.challenge;
    req.session.currentUser = finalUsername;
    req.session.isEntraIdRegistration = isEntraIdUser;
    
    console.log('Stored challenge in session:', options.challenge);
    console.log('Stored user in session:', finalUsername);
    console.log('Entra ID registration:', isEntraIdUser);

    res.json({
      ...options,
      enterpriseMode: isEntraIdUser,
      userInfo: {
        username: user.username,
        displayName: user.displayName,
        entraId: isEntraIdUser
      }
    });
  } catch (error) {
    console.error('Registration options error:', error);
    res.status(500).json({ error: 'Failed to generate registration options' });
  }
});

/**
 * Verify registration response and complete passkey registration
 */
app.post('/api/webauthn/verify-registration', async (req, res) => {
  try {
    const body = req.body; // Use req.body directly instead of destructuring
    console.log('Registration verification request:', JSON.stringify(body, null, 2));
    
    const expectedChallenge = req.session.currentChallenge;
    const username = req.session.currentUser;

    console.log('Expected challenge:', expectedChallenge);
    console.log('Current user:', username);

    if (!expectedChallenge || !username) {
      console.log('Missing challenge or username in session');
      return res.status(400).json({ error: 'No active registration session' });
    }

    const user = users.get(username);
    if (!user) {
      console.log('User not found:', username);
      return res.status(400).json({ error: 'User not found' });
    }

    const verification = await verifyRegistrationResponse({
      response: body,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: false,
    });

    const { verified, registrationInfo } = verification;

    if (verified && registrationInfo) {
      // Extract from registrationInfo.credential object (correct structure for @simplewebauthn/server)
      const credential = registrationInfo.credential;
      const credentialID = credential?.id;
      const credentialPublicKey = credential?.publicKey;  
      const counter = credential?.counter || 0;
      const { credentialDeviceType, credentialBackedUp } = registrationInfo;

      console.log('Registration verification successful!');
      console.log('Registration info keys:', Object.keys(registrationInfo));
      console.log('🔍 FULL registrationInfo object:', JSON.stringify(registrationInfo, null, 2));
      console.log('🔍 CREDENTIAL object keys:', credential ? Object.keys(credential) : 'credential is undefined');
      console.log('🔍 CREDENTIAL object:', credential);
      console.log('Credential ID from credential object:', credentialID);
      console.log('Credential ID type:', typeof credentialID);
      console.log('Credential ID constructor:', credentialID ? credentialID.constructor.name : 'undefined');
      console.log('🔍 DEBUGGING - credentialPublicKey from credential:', credentialPublicKey);
      console.log('🔍 DEBUGGING - credentialPublicKey type:', typeof credentialPublicKey);
      console.log('🔍 DEBUGGING - counter from credential:', counter);
      console.log('🔍 DEBUGGING - counter type:', typeof counter);

      // Check if credentialID is missing and try to get it from the body
      let finalCredentialID = credentialID;
      if (!finalCredentialID && body.rawId) {
        console.log('Using rawId as credential ID');
        finalCredentialID = Buffer.from(body.rawId, 'base64url');
      }

      if (!finalCredentialID) {
        console.error('No credential ID found in registration response');
        return res.status(400).json({ error: 'Missing credential ID in registration response' });
      }

      // Enhanced authenticator data for Entra ID users
      const isEntraIdRegistration = req.session.isEntraIdRegistration;
      const passkeyId = uuidv4();
      
      const newAuthenticator = {
        id: passkeyId,
        credentialID: finalCredentialID,
        credentialPublicKey,
        counter,
        credentialDeviceType,
        credentialBackedUp,
        transports: body.response.transports || [],
        createdAt: new Date().toISOString(),
        // Enhanced metadata for enterprise users
        ...(isEntraIdRegistration && {
          entraIdMetadata: {
            registeredByTenant: req.session.entraUser?.tenantId,
            registeredByUser: req.session.entraUser?.userId,
            attestationType: registrationInfo.attestationObject ? 'direct' : 'none',
            deviceTrust: credentialBackedUp ? 'synced' : 'device-bound'
          }
        }),
        // Encrypt sensitive data for local storage
        encryptedMetadata: encryptData({
          userAgent: req.get('User-Agent'),
          ipAddress: req.ip,
          registrationTimestamp: Date.now(),
          sessionId: req.sessionID
        })
      };

      user.authenticators.push(newAuthenticator);
      users.set(username, user);
      saveUsers(users); // Persist to file
      
      // Update passkey registry for Entra ID users
      if (isEntraIdRegistration && req.session.entraUser) {
        const userPasskeys = passkeyRegistry.get(req.session.entraUser.userPrincipalName) || [];
        userPasskeys.push({
          passkeyId: passkeyId,
          credentialId: Buffer.isBuffer(finalCredentialID) ? finalCredentialID.toString('base64url') : base64url.encode(finalCredentialID),
          deviceType: credentialDeviceType,
          createdAt: new Date().toISOString(),
          lastUsed: new Date().toISOString()
        });
        passkeyRegistry.set(req.session.entraUser.userPrincipalName, userPasskeys);
        savePasskeyRegistry(passkeyRegistry);
        
        console.log('Updated passkey registry for Entra ID user:', req.session.entraUser.userPrincipalName);
      }
      
      console.log('Stored authenticator with credential ID:', newAuthenticator.credentialID);
      console.log('Total authenticators for user:', user.authenticators.length);
      console.log('Enterprise registration:', isEntraIdRegistration);

      // Clear session data
      delete req.session.currentChallenge;
      delete req.session.currentUser;
      delete req.session.isEntraIdRegistration;

      res.json({ 
        verified: true, 
        message: 'Passkey registered successfully',
        passkeyInfo: {
          id: passkeyId,
          deviceType: credentialDeviceType,
          backedUp: credentialBackedUp,
          transports: body.response.transports || [],
          enterpriseMode: isEntraIdRegistration,
          userVerification: registrationInfo.userVerified
        },
        userInfo: {
          username: user.username,
          displayName: user.displayName,
          totalPasskeys: user.authenticators.length,
          entraIdLinked: !!user.entraId
        }
      });
    } else {
      res.status(400).json({ error: 'Registration verification failed', verified });
    }
  } catch (error) {
    console.error('Registration verification error:', error);
    res.status(500).json({ error: 'Registration verification failed' });
  }
});

// WebAuthn Authentication Endpoints

/**
 * Generate authentication options for passkey login
 */
app.post('/api/webauthn/generate-authentication-options', async (req, res) => {
  try {
    const { username } = req.body;

    let allowCredentials = [];

    if (username) {
      // User-specific authentication
      const user = users.get(username);
      if (user) {
        allowCredentials = user.authenticators.map(authenticator => ({
          id: authenticator.credentialID,
          type: 'public-key',
          transports: authenticator.transports,
        }));
      }
    }

    const options = await generateAuthenticationOptions({
      timeout: 60000,
      allowCredentials,
      userVerification: 'preferred',
      rpID,
    });

    // Store challenge in session
    req.session.currentChallenge = options.challenge;
    if (username) {
      req.session.currentUser = username;
    }

    res.json(options);
  } catch (error) {
    console.error('Authentication options error:', error);
    res.status(500).json({ error: 'Failed to generate authentication options' });
  }
});

/**
 * Verify authentication response and complete passkey login
 */
app.post('/api/webauthn/verify-authentication', async (req, res) => {
  try {
    const body = req.body;
    console.log('Authentication request body:', JSON.stringify(body, null, 2));
    
    const expectedChallenge = req.session.currentChallenge;

    if (!expectedChallenge) {
      console.log('No expected challenge in session');
      return res.status(400).json({ error: 'No active authentication session' });
    }

    if (!body || !body.id) {
      console.log('Missing credential ID in request body');
      return res.status(400).json({ error: 'Invalid authentication response - missing credential ID' });
    }

    // Extract user information from the userHandle in the passkey response
    let userId, username;
    
    if (body.response && body.response.userHandle) {
      try {
        // Decode the userHandle to get user information
        const userHandleBuffer = Buffer.from(body.response.userHandle, 'base64url');
        const userHandleString = userHandleBuffer.toString('utf-8');
        console.log('User handle decoded:', userHandleString);
        
        // For our implementation, we can use the userHandle as the user ID
        // and create a username from it or use a default pattern
        userId = userHandleString;
        username = `user-${userId.substring(0, 8)}`; // Create a readable username
        
        console.log('Extracted user info - ID:', userId, 'Username:', username);
      } catch (err) {
        console.error('Error decoding userHandle:', err);
        return res.status(400).json({ error: 'Invalid user handle in authentication response' });
      }
    } else {
      console.log('No userHandle in authentication response');
      return res.status(400).json({ error: 'Missing user handle in authentication response' });
    }

    // Create a minimal authenticator object for verification
    // Since we don't have stored authenticators, we'll let the verification handle it
    console.log('Attempting authentication without pre-stored user data');
    console.log('Credential ID:', body.id);

    // First try to find user by userHandle (preferred method)
    console.log('Looking for user by userHandle...');
    console.log('Available users:', Array.from(users.keys()));
    console.log('Looking for userHandle:', userId);

    let authenticator;
    let user;

    // Try to find user by userHandle first
    for (const [storedUsername, userData] of users.entries()) {
      if (userData.userHandleString === userId) {
        console.log('Found user by userHandle:', storedUsername);
        user = userData;
        // Find the matching authenticator by credential ID
        console.log(`User ${storedUsername} has ${userData.authenticators.length} authenticators`);
        const foundAuth = userData.authenticators.find(auth => {
          try {
            if (!auth.credentialID) {
              console.log('Authenticator has no credentialID, skipping');
              return false;
            }
            
            console.log('Comparing credential IDs:');
            console.log('Stored:', Buffer.isBuffer(auth.credentialID) ? auth.credentialID.toString('base64url') : auth.credentialID);
            console.log('Request:', body.id);
            
            const authCredentialBuffer = Buffer.isBuffer(auth.credentialID) 
              ? auth.credentialID 
              : Buffer.from(auth.credentialID, 'base64url');
            const responseCredentialBuffer = Buffer.from(body.id, 'base64url');
            
            const matches = authCredentialBuffer.equals(responseCredentialBuffer);
            console.log('Credential match result:', matches);
            return matches;
          } catch (err) {
            console.log('Credential ID comparison error:', err);
            return false;
          }
        });
        
        if (foundAuth) {
          console.log('Found authenticator for user by userHandle');
          authenticator = foundAuth;
          break;
        } else {
          console.log('No matching authenticator found for this credential ID');
        }
      }
    }

    // If not found by userHandle, try by credential ID (fallback)
    if (!authenticator && !user) {
      console.log('User not found by userHandle, trying credential ID lookup...');
      for (const [storedUsername, userData] of users.entries()) {
        console.log(`Checking stored user ${storedUsername} with ${userData.authenticators.length} authenticators`);
        
        const foundAuth = userData.authenticators.find(auth => {
          try {
            if (!auth.credentialID) {
              console.log('Authenticator has no credentialID, skipping');
              return false;
            }
            
            console.log('Stored credential ID:', auth.credentialID);
            console.log('Request credential ID:', body.id);
            
            const authCredentialBuffer = Buffer.isBuffer(auth.credentialID) 
              ? auth.credentialID 
              : Buffer.from(auth.credentialID, 'base64url');
            const responseCredentialBuffer = Buffer.from(body.id, 'base64url');
            
            const matches = authCredentialBuffer.equals(responseCredentialBuffer);
            console.log('Credential ID matches:', matches);
            return matches;
          } catch (err) {
            console.log('Credential ID comparison error:', err);
            return false;
          }
        });
        
        if (foundAuth) {
          console.log('Found matching stored authenticator for user:', storedUsername);
          authenticator = foundAuth;
          user = userData;
          break;
        }
      }
    }

    if (authenticator && user) {
      console.log('Using stored authenticator data for verification');
      console.log('Authenticator details:', {
        hasCredentialID: !!authenticator.credentialID,
        hasCredentialPublicKey: !!authenticator.credentialPublicKey,
        counter: authenticator.counter,
        transports: authenticator.transports
      });
      
      try {
        // Try verification with stored authenticator data
        const verification = await verifyAuthenticationResponse({
          response: body,
          expectedChallenge,
          expectedOrigin: origin,
          expectedRPID: rpID,
          authenticator: {
            credentialID: authenticator.credentialID,
            credentialPublicKey: authenticator.credentialPublicKey,
            counter: authenticator.counter || 0,
            transports: authenticator.transports || [],
          },
          requireUserVerification: false,
        });

        if (verification.verified) {
          console.log('Authentication successful using stored data');
          
          // Update counter
          authenticator.counter = verification.authenticationInfo.newCounter;

          // Create session
          const sessionId = crypto.randomUUID();
          const sessionData = {
            userId: user.id,
            username: user.username,
            loginTime: new Date().toISOString(),
            lastActivity: new Date().toISOString()
          };

          userSessions.set(sessionId, sessionData);
          saveSessions(userSessions); // Persist to file
          req.session.sessionId = sessionId;
          req.session.userId = user.id;
          req.session.username = user.username;

          // Clear challenge
          delete req.session.currentChallenge;
          delete req.session.currentUser;

          res.json({ 
            verified: true, 
            user: {
              id: user.id,
              username: user.username,
              displayName: user.displayName
            },
            sessionId 
          });
        } else {
          console.log('Authentication verification failed with stored data');
          res.status(400).json({ error: 'Authentication verification failed', verified: false });
        }
      } catch (error) {
        console.error('Authentication verification error with stored data:', error);
        res.status(500).json({ error: 'Authentication verification failed' });
      }
    } else {
      console.log('No stored authenticator found - this requires user registration first');
      res.status(400).json({ 
        error: 'Authenticator not found. Please register your passkey first.',
        requireRegistration: true
      });
    }
  } catch (error) {
    console.error('Authentication verification error:', error);
    res.status(500).json({ error: 'Authentication verification failed' });
  }
});

// Session Management Endpoints

/**
 * Get current user session info
 */
app.get('/api/auth/session', (req, res) => {
  const sessionId = req.session.sessionId;
  
  if (!sessionId) {
    return res.status(401).json({ error: 'No active session' });
  }

  const sessionData = userSessions.get(sessionId);
  if (!sessionData) {
    return res.status(401).json({ error: 'Invalid session' });
  }

  // Update last activity
  sessionData.lastActivity = new Date().toISOString();
  userSessions.set(sessionId, sessionData);

  const user = users.get(sessionData.username);
  if (!user) {
    return res.status(401).json({ error: 'User not found' });
  }

  res.json({
    user: {
      id: user.id,
      username: user.username,
      displayName: user.displayName
    },
    session: {
      loginTime: sessionData.loginTime,
      lastActivity: sessionData.lastActivity
    }
  });
});

/**
 * Logout and destroy session
 */
app.post('/api/auth/logout', (req, res) => {
  const sessionId = req.session.sessionId;
  
  if (sessionId) {
    userSessions.delete(sessionId);
  }

  req.session.destroy((err) => {
    if (err) {
      console.error('Session destruction error:', err);
      return res.status(500).json({ error: 'Logout failed' });
    }
    
    res.clearCookie('connect.sid');
    res.json({ message: 'Logged out successfully' });
  });
});

// User Management Endpoints

/**
 * Get all registered users (for demo purposes)
 */
app.get('/api/users', (req, res) => {
  const userList = Array.from(users.values()).map(user => ({
    id: user.id,
    username: user.username,
    displayName: user.displayName,
    authenticatorCount: user.authenticators.length,
    createdAt: user.createdAt,
    passkeys: user.authenticators.map((auth, index) => ({
      id: Buffer.isBuffer(auth.credentialID) ? auth.credentialID.toString('base64url') : auth.credentialID,
      counter: auth.counter || 0,
      createdAt: auth.createdAt || new Date().toISOString(),
      name: `Passkey ${index + 1}`,
      transports: auth.transports || []
    }))
  }));

  res.json(userList);
});

/**
 * Get user by username
 */
app.get('/api/users/:username', (req, res) => {
  const { username } = req.params;
  const user = users.get(username);

  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  res.json({
    id: user.id,
    username: user.username,
    displayName: user.displayName,
    authenticatorCount: user.authenticators.length,
    createdAt: user.createdAt
  });
});

// Delete a specific passkey/authenticator for a user
app.delete('/api/users/:username/passkeys/:credentialId', (req, res) => {
  try {
    const { username, credentialId } = req.params;
    console.log(`Delete passkey request: username=${username}, credentialId=${credentialId}`);

    const user = users.get(username);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const credentialBuffer = Buffer.from(credentialId, 'base64url');
    const initialCount = user.authenticators.length;
    
    // Remove the authenticator with matching credential ID
    user.authenticators = user.authenticators.filter(auth => {
      try {
        const authCredentialBuffer = Buffer.isBuffer(auth.credentialID) 
          ? auth.credentialID 
          : Buffer.from(auth.credentialID, 'base64url');
        
        return !authCredentialBuffer.equals(credentialBuffer);
      } catch (error) {
        console.warn('Error comparing credential IDs:', error);
        return true; // Keep authenticator if comparison fails
      }
    });

    const finalCount = user.authenticators.length;
    const deleted = initialCount > finalCount;

    if (deleted) {
      // Update the user in storage
      users.set(username, user);
      saveUsers(users);
      
      console.log(`Successfully deleted passkey for user ${username}. Remaining: ${finalCount}`);
      
      res.json({ 
        success: true, 
        message: 'Passkey deleted successfully',
        remainingPasskeys: finalCount
      });
    } else {
      res.status(404).json({ error: 'Passkey not found' });
    }
  } catch (error) {
    console.error('Error deleting passkey:', error);
    res.status(500).json({ error: 'Failed to delete passkey' });
  }
});

// Delete all passkeys for a user
app.delete('/api/users/:username/passkeys', (req, res) => {
  try {
    const { username } = req.params;
    console.log(`Delete all passkeys request: username=${username}`);

    const user = users.get(username);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const deletedCount = user.authenticators.length;
    user.authenticators = [];
    
    // Update the user in storage
    users.set(username, user);
    saveUsers(users);
    
    console.log(`Successfully deleted ${deletedCount} passkeys for user ${username}`);
    
    res.json({ 
      success: true, 
      message: `Deleted ${deletedCount} passkeys successfully`,
      deletedCount: deletedCount
    });
  } catch (error) {
    console.error('Error deleting all passkeys:', error);
    res.status(500).json({ error: 'Failed to delete passkeys' });
  }
});

// Protected API endpoints (require authentication)
const requireAuth = (req, res, next) => {
  const sessionId = req.session.sessionId;
  
  if (!sessionId || !userSessions.has(sessionId)) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const sessionData = userSessions.get(sessionId);
  sessionData.lastActivity = new Date().toISOString();
  userSessions.set(sessionId, sessionData);

  req.user = sessionData;
  next();
};

/**
 * Protected endpoint example
 */
app.get('/api/protected/profile', requireAuth, (req, res) => {
  const user = users.get(req.user.username);
  
  res.json({
    message: 'This is a protected endpoint',
    user: {
      id: user.id,
      username: user.username,
      displayName: user.displayName,
      createdAt: user.createdAt
    },
    session: req.user
  });
});

// Serve React app for all other routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../dist/index.html'));
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ error: 'Internal server error' });
});

// Clean up old sessions periodically
setInterval(() => {
  const now = Date.now();
  const maxAge = 24 * 60 * 60 * 1000; // 24 hours

  for (const [sessionId, sessionData] of userSessions.entries()) {
    const lastActivity = new Date(sessionData.lastActivity).getTime();
    if (now - lastActivity > maxAge) {
      userSessions.delete(sessionId);
      console.log(`Cleaned up expired session: ${sessionId}`);
    }
  }
}, 60 * 60 * 1000); // Run every hour

app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`📱 WebAuthn RP ID: ${rpID}`);
  console.log(`🌐 Origin: ${origin}`);
  console.log(`🔒 Session secret: ${process.env.SESSION_SECRET ? 'Configured' : 'Generated (use SESSION_SECRET env var in production)'}`);
});

module.exports = app;
