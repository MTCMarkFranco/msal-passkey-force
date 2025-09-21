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
// MSAL no longer needed - using pure custom polling
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

// Enhanced rate limiting for multi-user kiosk scenarios
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 500, // Increased for concurrent users
  message: {
    error: 'Too many requests from this IP, please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false,
  // Skip rate limiting for local development
  skip: (req) => {
    return process.env.NODE_ENV === 'development' && 
           (req.ip === '127.0.0.1' || req.ip === '::1' || req.ip?.startsWith('192.168.'));
  }
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

// Pure Custom Device Code Flow - No MSAL dependency
// We make direct HTTP requests to Microsoft's OAuth endpoints for complete control

// In-memory store for device code sessions (use Redis in production)
const deviceCodeSessions = new Map();

// Session metrics for monitoring concurrent users
const sessionMetrics = {
  totalSessions: 0,
  activeSessions: 0,
  completedSessions: 0,
  failedSessions: 0,
  getActiveSessionCount: () => {
    let active = 0;
    for (const session of deviceCodeSessions.values()) {
      if (session.status === 'pending') active++;
    }
    return active;
  },
  logMetrics: () => {
    const active = sessionMetrics.getActiveSessionCount();
    console.log(`[METRICS] Active: ${active}, Total: ${sessionMetrics.totalSessions}, Completed: ${sessionMetrics.completedSessions}, Failed: ${sessionMetrics.failedSessions}`);
  }
};

// Clean up expired sessions every 5 minutes
setInterval(() => {
  const now = Date.now();
  let cleaned = 0;
  
  for (const [sessionId, session] of deviceCodeSessions.entries()) {
    const sessionAge = (now - session.timestamp) / 1000;
    if (sessionAge > session.expiresIn + 300) { // Add 5 minute buffer
      deviceCodeSessions.delete(sessionId);
      cleaned++;
    }
  }
  
  if (cleaned > 0) {
    console.log(`[CLEANUP] Removed ${cleaned} expired sessions`);
  }
}, 300000); // Run every 5 minutes

/**
 * Device Code Authentication Flow for Kiosk - Pure Custom Polling
 * This implements the strongest security for kiosk scenarios without MSAL's internal polling
 */
app.post('/auth/device-code/start', async (req, res) => {
  try {
    const sessionId = uuidv4();
    const scopes = process.env.DEFAULT_SCOPES?.split(',') || ['openid', 'profile', 'User.Read'];

    console.log(`[AUTH] Starting pure custom device code flow for session: ${sessionId}`);
    
    // Update session metrics
    sessionMetrics.totalSessions++;
    sessionMetrics.logMetrics();

    // Make direct request to Microsoft's device code endpoint
    const clientId = process.env.CLIENT_ID;
    const tenantId = process.env.TENANT_ID || 'common';
    const authority = `https://login.microsoftonline.com/${tenantId}`;
    
    const deviceCodeEndpoint = `${authority}/oauth2/v2.0/devicecode`;
    const tokenEndpoint = `${authority}/oauth2/v2.0/token`;

    console.log(`[DEBUG] Device code request to: ${deviceCodeEndpoint}`);
    console.log(`[DEBUG] Using client_id: ${clientId}`);
    console.log(`[DEBUG] Using scopes: ${scopes.join(' ')}`);

    // Step 1: Get device code from Microsoft
    const deviceCodeResponse = await fetch(deviceCodeEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        client_id: clientId,
        scope: scopes.join(' ')
      })
    });

    if (!deviceCodeResponse.ok) {
      const errorText = await deviceCodeResponse.text();
      throw new Error(`Device code request failed: ${deviceCodeResponse.status} ${errorText}`);
    }

    const deviceCodeData = await deviceCodeResponse.json();
    
    console.log(`[DEVICE CODE] User code: ${deviceCodeData.user_code}`);
    console.log(`[DEVICE CODE] Device code expires in: ${deviceCodeData.expires_in} seconds`);
    console.log(`[DEVICE CODE] Polling interval: ${deviceCodeData.interval} seconds`);

    // Store session data for pure custom polling
    deviceCodeSessions.set(sessionId, {
      deviceCode: deviceCodeData.device_code,
      userCode: deviceCodeData.user_code,
      verificationUri: deviceCodeData.verification_uri,
      expiresIn: deviceCodeData.expires_in,
      interval: deviceCodeData.interval,
      message: deviceCodeData.message,
      timestamp: Date.now(),
      status: 'pending',
      processed: false,
      // Store endpoints for custom polling
      tokenEndpoint: tokenEndpoint,
      clientId: clientId,
      scopes: scopes
    });

    const session = deviceCodeSessions.get(sessionId);
    if (!session) {
      throw new Error('Failed to initialize device code session');
    }

    // Don't store the promise to avoid conflicts with MSAL's internal polling

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
 * Poll for authentication status with pure custom polling
 * This endpoint polls Microsoft's token endpoint directly when status is pending
 */
app.get('/auth/device-code/status/:sessionId', async (req, res) => {
  try {
    const { sessionId } = req.params;
    const session = deviceCodeSessions.get(sessionId);

    console.log(`[AUTH] Status check for session ${sessionId}: ${session ? session.status : 'NOT_FOUND'}`);

    if (!session) {
      return res.status(404).json({ error: 'Session not found' });
    }

    // Check if session expired
    const now = Date.now();
    const sessionAge = (now - session.timestamp) / 1000; // seconds
    if (sessionAge > session.expiresIn) {
      console.log(`[AUTH] Session ${sessionId} expired (age: ${sessionAge}s, expires: ${session.expiresIn}s)`);
      // Don't delete immediately if completed to allow client to retrieve result
      if (session.status !== 'completed') {
        deviceCodeSessions.delete(sessionId);
      }
      return res.json({ status: 'expired' });
    }

    // If still pending and not processed, poll Microsoft's token endpoint
    if (session.status === 'pending' && !session.processed) {
      console.log(`[AUTH] Polling token endpoint for session ${sessionId}`);
      
      try {
        console.log(`[DEBUG] Polling token endpoint: ${session.tokenEndpoint}`);
        console.log(`[DEBUG] Using client_id: ${session.clientId}`);
        console.log(`[DEBUG] Using device_code: ${session.deviceCode.substring(0, 10)}...`);
        
        const tokenResponse = await fetch(session.tokenEndpoint, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          },
          body: new URLSearchParams({
            grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
            client_id: session.clientId,
            device_code: session.deviceCode
          })
        });

        const tokenData = await tokenResponse.json();

        console.log(`[DEBUG] Token response status: ${tokenResponse.status}`);
        console.log(`[DEBUG] Token response data:`, JSON.stringify(tokenData, null, 2));

        if (tokenResponse.ok) {
          // Success - user completed authentication
          console.log(`[AUTH] Device code authentication successful for session: ${sessionId}`);
          session.processed = true;
          session.status = 'completed';
          sessionMetrics.completedSessions++;
          session.authResult = {
            accessToken: tokenData.access_token,
            idToken: tokenData.id_token,
            tokenType: tokenData.token_type,
            scopes: session.scopes,
            expiresOn: new Date(Date.now() + (tokenData.expires_in * 1000)),
            // Create minimal account object from token data
            account: (() => {
              let tokenPayload = null;
              try {
                tokenPayload = tokenData.id_token ? JSON.parse(Buffer.from(tokenData.id_token.split('.')[1], 'base64').toString()) : null;
              } catch (e) {
                console.warn(`[AUTH] Failed to parse ID token for session ${sessionId}:`, e);
              }
              
              return {
                homeAccountId: tokenData.client_info ? Buffer.from(tokenData.client_info, 'base64').toString() : sessionId,
                environment: 'login.microsoftonline.com',
                tenantId: tokenPayload?.tid || 'unknown',
                username: tokenPayload?.preferred_username || tokenPayload?.upn || 'unknown',
                name: tokenPayload?.name || 'Unknown User'
              };
            })()
          };
          console.log(`[AUTH] Session ${sessionId} marked as completed`);
        } else if (tokenData.error === 'authorization_pending') {
          // User hasn't completed authentication yet - this is expected
          console.log(`[AUTH] Session ${sessionId} still pending user authentication`);
        } else if (tokenData.error === 'authorization_declined') {
          // User declined authentication
          console.log(`[AUTH] Session ${sessionId} authentication declined by user`);
          session.processed = true;
          session.status = 'failed';
          session.error = 'Authentication declined by user';
          sessionMetrics.failedSessions++;
        } else if (tokenData.error === 'expired_token') {
          // Device code expired
          console.log(`[AUTH] Session ${sessionId} device code expired`);
          session.processed = true;
          session.status = 'failed';
          session.error = 'Device code expired';
          sessionMetrics.failedSessions++;
        } else {
          // Other error
          console.error(`[AUTH] Session ${sessionId} authentication failed:`, tokenData.error_description || tokenData.error);
          session.processed = true;
          session.status = 'failed';
          session.error = tokenData.error_description || tokenData.error;
        }
      } catch (pollError) {
        console.error(`[AUTH] Polling failed for session ${sessionId}:`, pollError);
        // Don't mark as failed on network errors, keep retrying
      }
    }

    // Return status without sensitive data
    const response = {
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
    };

    console.log(`[AUTH] Returning status for ${sessionId}:`, response.status);
    res.json(response);

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

/**
 * Session metrics endpoint for monitoring concurrent users
 */
app.get('/auth/metrics', (req, res) => {
  const activeCount = sessionMetrics.getActiveSessionCount();
  const totalSessions = deviceCodeSessions.size;
  
  res.json({
    concurrent_users: activeCount,
    total_sessions: sessionMetrics.totalSessions,
    active_sessions: activeCount,
    stored_sessions: totalSessions,
    completed_sessions: sessionMetrics.completedSessions,
    failed_sessions: sessionMetrics.failedSessions,
    timestamp: new Date().toISOString()
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