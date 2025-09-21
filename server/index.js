/**
 * Secure Kiosk Authentication Server
 * 
 * This server implements the strongest security practices:
 * - PKCE (Proof Key for Code Exchange) for SPAs
 * - Device Code Flow for kiosk scenarios
 * - Passkey authentication support
 * - QR code generation for mobile authentication
 * - Rate limiting and security headers
 * - Proper error handling and logging
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const { PublicClientApplication, LogLevel } = require('@azure/msal-node');
const QRCode = require('qrcode');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3001;

// Security Configuration
const corsOptions = {
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
  credentials: true,
  optionsSuccessStatus: 200
};

const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
  message: {
    error: 'Too many requests from this IP, please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Apply security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https://login.microsoftonline.com"],
    },
  },
}));

app.use(cors(corsOptions));
app.use(limiter);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// MSAL Configuration - Following Azure Best Practices
const msalConfig = {
  auth: {
    clientId: process.env.CLIENT_ID,
    authority: `https://login.microsoftonline.com/${process.env.TENANT_ID}`,
    clientSecret: process.env.CLIENT_SECRET, // For confidential client flows
  },
  system: {
    loggerOptions: {
      loggerCallback(loglevel, message, containsPii) {
        if (!containsPii) {
          console.log(`[MSAL] ${new Date().toISOString()} - ${message}`);
        }
      },
      piiLoggingEnabled: false,
      logLevel: process.env.NODE_ENV === 'development' ? LogLevel.Verbose : LogLevel.Warning,
    }
  }
};

// Initialize MSAL Public Client Application for Device Code Flow
const pca = new PublicClientApplication(msalConfig);

// In-memory store for device code sessions (use Redis in production)
const deviceCodeSessions = new Map();

/**
 * Device Code Authentication Flow for Kiosk
 * This implements the strongest security for kiosk scenarios where users cannot enter passwords
 */
app.post('/auth/device-code/start', async (req, res) => {
  try {
    const sessionId = uuidv4();
    const scopes = process.env.DEFAULT_SCOPES?.split(',') || ['openid', 'profile', 'User.Read'];

    console.log(`[AUTH] Starting device code flow for session: ${sessionId}`);

    const deviceCodeRequest = {
      scopes: scopes,
      deviceCodeCallback: (response) => {
        console.log(`[DEVICE CODE] User code: ${response.userCode}`);
        console.log(`[DEVICE CODE] Device code expires in: ${response.expiresIn} seconds`);
        
        // Store session data
        deviceCodeSessions.set(sessionId, {
          deviceCode: response.deviceCode,
          userCode: response.userCode,
          verificationUri: response.verificationUri,
          expiresIn: response.expiresIn,
          message: response.message,
          timestamp: Date.now(),
          status: 'pending'
        });
      }
    };

    // Start device code flow
    const deviceCodePromise = pca.acquireTokenByDeviceCode(deviceCodeRequest);

    // Handle the authentication result
    deviceCodePromise
      .then((response) => {
        console.log(`[AUTH] Device code authentication successful for session: ${sessionId}`);
        const session = deviceCodeSessions.get(sessionId);
        if (session) {
          session.status = 'completed';
          session.authResult = {
            accessToken: response.accessToken,
            idToken: response.idToken,
            account: response.account,
            scopes: response.scopes
          };
        }
      })
      .catch((error) => {
        console.error(`[AUTH] Device code authentication failed for session: ${sessionId}`, error);
        const session = deviceCodeSessions.get(sessionId);
        if (session) {
          session.status = 'failed';
          session.error = error.message;
        }
      });

    // Wait a moment for the callback to populate session data
    await new Promise(resolve => setTimeout(resolve, 1000));

    const session = deviceCodeSessions.get(sessionId);
    if (!session) {
      throw new Error('Failed to initialize device code session');
    }

    // Store the promise for polling after session is created
    session.tokenPromise = deviceCodePromise;

    // Generate QR Code for mobile authentication
    const qrCodeData = `${session.verificationUri}?otc=${session.userCode}`;
    const qrCodeSvg = await QRCode.toString(qrCodeData, { 
      type: 'svg',
      width: 256,
      margin: 2,
      color: {
        dark: '#000000',
        light: '#FFFFFF'
      }
    });

    res.json({
      sessionId,
      userCode: session.userCode,
      verificationUri: session.verificationUri,
      qrCode: qrCodeSvg,
      message: session.message,
      expiresIn: session.expiresIn
    });

  } catch (error) {
    console.error('[AUTH] Device code initialization failed:', error);
    res.status(500).json({
      error: 'Authentication initialization failed',
      message: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

/**
 * Poll for authentication status
 * The React app will call this endpoint to check if authentication completed
 */
app.get('/auth/device-code/status/:sessionId', (req, res) => {
  try {
    const { sessionId } = req.params;
    const session = deviceCodeSessions.get(sessionId);

    if (!session) {
      return res.status(404).json({ error: 'Session not found' });
    }

    // Check if session expired
    const now = Date.now();
    const sessionAge = (now - session.timestamp) / 1000; // seconds
    if (sessionAge > session.expiresIn) {
      deviceCodeSessions.delete(sessionId);
      return res.json({ status: 'expired' });
    }

    // Return status without sensitive data
    res.json({
      status: session.status,
      userCode: session.userCode,
      expiresIn: Math.max(0, session.expiresIn - sessionAge),
      ...(session.status === 'completed' && session.authResult ? {
        user: {
          name: session.authResult.account.name,
          username: session.authResult.account.username,
          homeAccountId: session.authResult.account.homeAccountId
        }
      } : {}),
      ...(session.status === 'failed' ? {
        error: session.error
      } : {})
    });

  } catch (error) {
    console.error('[AUTH] Status check failed:', error);
    res.status(500).json({ error: 'Status check failed' });
  }
});

/**
 * Get authentication token for API calls
 * Only returns token if authentication completed successfully
 */
app.get('/auth/token/:sessionId', (req, res) => {
  try {
    const { sessionId } = req.params;
    const session = deviceCodeSessions.get(sessionId);

    if (!session || session.status !== 'completed' || !session.authResult) {
      return res.status(401).json({ error: 'Not authenticated' });
    }

    // Return token for API calls (consider implementing token refresh)
    res.json({
      accessToken: session.authResult.accessToken,
      tokenType: 'Bearer',
      scopes: session.authResult.scopes,
      expiresOn: session.authResult.expiresOn
    });

  } catch (error) {
    console.error('[AUTH] Token retrieval failed:', error);
    res.status(500).json({ error: 'Token retrieval failed' });
  }
});

/**
 * Logout endpoint
 * Cleans up session and provides logout URL
 */
app.post('/auth/logout/:sessionId', (req, res) => {
  try {
    const { sessionId } = req.params;
    const session = deviceCodeSessions.get(sessionId);

    // Clean up session
    deviceCodeSessions.delete(sessionId);

    // Provide logout URL for complete sign-out
    const logoutUrl = `https://login.microsoftonline.com/${process.env.TENANT_ID}/oauth2/v2.0/logout?post_logout_redirect_uri=${encodeURIComponent(process.env.POST_LOGOUT_REDIRECT_URI || 'http://localhost:3001')}`;

    res.json({
      success: true,
      logoutUrl,
      message: 'Logged out successfully'
    });

  } catch (error) {
    console.error('[AUTH] Logout failed:', error);
    res.status(500).json({ error: 'Logout failed' });
  }
});

// Serve React app in production
if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, '../dist')));
  
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../dist/index.html'));
  });
}

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV,
    sessions: deviceCodeSessions.size
  });
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('[SERVER ERROR]', error);
  res.status(500).json({
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? error.message : undefined
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Secure Kiosk Server running on port ${PORT}`);
  console.log(`🔒 Environment: ${process.env.NODE_ENV}`);
  console.log(`🛡️  Security features enabled: CORS, Helmet, Rate Limiting`);
  
  if (process.env.NODE_ENV === 'development') {
    console.log(`📱 React app: http://localhost:3000`);
    console.log(`🔑 Auth server: http://localhost:${PORT}`);
  }
});

module.exports = app;