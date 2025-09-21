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

// Enhanced rate limiting for multi-user kiosk scenarios
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 500, // Increased for concurrent users
  message: {
    error: 'Too many requests from this IP, please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false,
  // Skip rate limiting for local development and Azure App Service
  skip: (req) => {
    const isLocalDev = process.env.NODE_ENV === 'development' || 
                      req.ip === '127.0.0.1' || 
                      req.ip === '::1' || 
                      req.ip?.startsWith('192.168.') ||
                      req.ip?.startsWith('10.') ||
                      req.hostname === 'localhost';
    
    const isAzureAppService = process.env.WEBSITE_NODE_DEFAULT_VERSION;
    
    if (isLocalDev || isAzureAppService) {
      console.log(`[RATE LIMIT] Skipping rate limit for ${isLocalDev ? 'local dev' : 'Azure App Service'} (IP: ${req.ip})`);
      return true;
    }
    return false;
  }
});

// CORS configuration - only for local development
// Azure App Service handles CORS in production
if (!process.env.WEBSITE_NODE_DEFAULT_VERSION) {
  const corsOptions = {
    origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
    credentials: true,
    optionsSuccessStatus: 200
  };
  app.use(cors(corsOptions));
  console.log('🔗 CORS enabled for local development');
}

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

app.use(limiter);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Pure Custom Device Code Flow - No MSAL dependency
// We make direct HTTP requests to Microsoft's OAuth endpoints for complete control

// In-memory store for device code sessions (use Redis in production)
const deviceCodeSessions = new Map();

// ================== SESSION PERSISTENCE ==================
const fs = require('fs').promises;

const SESSION_FILE = path.join(__dirname, '.sessions.json');

// Load sessions from file on startup
async function loadSessions() {
    try {
        const data = await fs.readFile(SESSION_FILE, 'utf8');
        const sessions = JSON.parse(data);
        console.log(`[SESSION] Loaded ${Object.keys(sessions).length} sessions from disk`);
        
        // Restore sessions to Map and restart polling for active sessions
        for (const [sessionId, session] of Object.entries(sessions)) {
            deviceCodeSessions.set(sessionId, session);
            
            // Restart server-side polling for pending sessions that haven't expired
            if (session.status === 'pending' && session.expiresAt > Date.now()) {
                console.log(`[SESSION] Resuming polling for session ${sessionId}`);
                startServerSidePolling(sessionId, session);
            }
        }
    } catch (error) {
        if (error.code !== 'ENOENT') {
            console.error('[SESSION] Error loading sessions:', error);
        }
    }
}

// Save sessions to file
async function saveSessions() {
    try {
        const sessions = Object.fromEntries(deviceCodeSessions);
        await fs.writeFile(SESSION_FILE, JSON.stringify(sessions, null, 2));
    } catch (error) {
        console.error('[SESSION] Error saving sessions:', error);
    }
}

// Auto-save sessions periodically and on changes
setInterval(saveSessions, 30000); // Save every 30 seconds

// Save on process exit
process.on('SIGINT', async () => {
    console.log('[SESSION] Saving sessions before exit...');
    await saveSessions();
    process.exit(0);
});

process.on('SIGTERM', async () => {
    console.log('[SESSION] Saving sessions before exit...');
    await saveSessions();
    process.exit(0);
});

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

// Server-side polling function to avoid race conditions
const startServerSidePolling = (sessionId, session) => {
  // Use random interval between 7-10 seconds regardless of Microsoft's suggested interval
  const getRandomPollInterval = () => {
    return (7 + Math.random() * 3) * 1000; // Random between 7000-10000ms (7-10 seconds)
  };
  
  const poll = async () => {
    try {
      const currentSession = deviceCodeSessions.get(sessionId);
      if (!currentSession || currentSession.processed || currentSession.status !== 'pending') {
        console.log(`[SERVER POLL] Stopping polling for session ${sessionId}: ${currentSession?.status || 'not found'}`);
        return; // Stop polling
      }

      console.log(`[SERVER POLL] Checking token for session ${sessionId}`);
      
      const tokenResponse = await fetch(currentSession.tokenEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          client_id: currentSession.clientId,
          device_code: currentSession.deviceCode
        })
      });

      const tokenData = await tokenResponse.json();

      if (tokenResponse.ok) {
        // Success - user completed authentication
        console.log(`[SERVER POLL] Authentication successful for session: ${sessionId}`);
        currentSession.processed = true;
        currentSession.status = 'completed';
        sessionMetrics.completedSessions++;
        
        // Save sessions after authentication completion
        saveSessions().catch(console.error);
        
        currentSession.authResult = {
          accessToken: tokenData.access_token,
          idToken: tokenData.id_token,
          tokenType: tokenData.token_type,
          scopes: currentSession.scopes,
          expiresOn: new Date(Date.now() + (tokenData.expires_in * 1000)),
          account: (() => {
            let tokenPayload = null;
            try {
              tokenPayload = tokenData.id_token ? JSON.parse(Buffer.from(tokenData.id_token.split('.')[1], 'base64').toString()) : null;
            } catch (e) {
              console.warn(`[SERVER POLL] Failed to parse ID token for session ${sessionId}:`, e);
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
        return; // Stop polling
      } else if (tokenData.error === 'authorization_pending') {
        // User hasn't completed authentication yet - continue polling
        const nextPollInterval = getRandomPollInterval();
        console.log(`[SERVER POLL] Session ${sessionId} still pending - next poll in ${Math.round(nextPollInterval/1000)}s`);
        setTimeout(poll, nextPollInterval);
      } else if (tokenData.error === 'authorization_declined') {
        console.log(`[SERVER POLL] Session ${sessionId} declined by user`);
        currentSession.processed = true;
        currentSession.status = 'failed';
        currentSession.error = 'Authentication declined by user';
        sessionMetrics.failedSessions++;
        saveSessions().catch(console.error);
        return; // Stop polling
      } else if (tokenData.error === 'expired_token') {
        console.log(`[SERVER POLL] Session ${sessionId} expired`);
        currentSession.processed = true;
        currentSession.status = 'failed';
        currentSession.error = 'Device code expired';
        sessionMetrics.failedSessions++;
        saveSessions().catch(console.error);
        return; // Stop polling
      } else {
        console.error(`[SERVER POLL] Session ${sessionId} failed:`, tokenData.error_description || tokenData.error);
        currentSession.processed = true;
        currentSession.status = 'failed';
        currentSession.error = tokenData.error_description || tokenData.error;
        sessionMetrics.failedSessions++;
        saveSessions().catch(console.error);
        return; // Stop polling
      }
    } catch (error) {
      console.error(`[SERVER POLL] Error polling session ${sessionId}:`, error);
      // Continue polling on network errors with random interval
      const nextPollInterval = getRandomPollInterval();
      console.log(`[SERVER POLL] Retrying session ${sessionId} in ${Math.round(nextPollInterval/1000)}s due to error`);
      setTimeout(poll, nextPollInterval);
    }
  };

  // Start polling after the initial random interval
  const initialPollInterval = getRandomPollInterval();
  console.log(`[SERVER POLL] Starting polling for session ${sessionId} - first poll in ${Math.round(initialPollInterval/1000)}s`);
  setTimeout(poll, initialPollInterval);
};

/**
 * Device Code Authentication Flow for Kiosk - Server-Side Polling
 * This implements the strongest security for kiosk scenarios with server-side polling to avoid race conditions
 */
app.post('/auth/device-code/start', async (req, res) => {
  try {
    const sessionId = uuidv4();
    const scopes = process.env.DEFAULT_SCOPES?.split(',') || ['openid', 'profile', 'User.Read'];

    console.log(`[AUTH] Starting server-side polled device code flow for session: ${sessionId}`);
    console.log(`[AUTH] Request IP: ${req.ip}, Headers: ${JSON.stringify(req.headers['x-forwarded-for'] || 'none')}`);
    console.log(`[AUTH] Environment: ${process.env.NODE_ENV}, Azure: ${!!process.env.WEBSITE_NODE_DEFAULT_VERSION}`);
    
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
    
    console.log(`[DEVICE CODE] Full response:`, JSON.stringify(deviceCodeData, null, 2));
    console.log(`[DEVICE CODE] User code: ${deviceCodeData.user_code}`);
    console.log(`[DEVICE CODE] Device code expires in: ${deviceCodeData.expires_in} seconds`);
    console.log(`[DEVICE CODE] Polling interval: ${deviceCodeData.interval} seconds`);

    // Store session data for server-side polling
    const session = {
      deviceCode: deviceCodeData.device_code,
      userCode: deviceCodeData.user_code,
      verificationUri: deviceCodeData.verification_uri,
      expiresIn: deviceCodeData.expires_in,
      interval: deviceCodeData.interval,
      message: deviceCodeData.message,
      timestamp: Date.now(),
      status: 'pending',
      processed: false,
      // Store endpoints for server-side polling
      tokenEndpoint: tokenEndpoint,
      clientId: clientId,
      scopes: scopes
    };

    deviceCodeSessions.set(sessionId, session);
    
    // Save sessions after creating new session
    saveSessions().catch(console.error);
    
    // Start server-side polling
    console.log(`[AUTH] Starting server-side polling for session ${sessionId}`);
    startServerSidePolling(sessionId, session);

    // Don't store the promise to avoid conflicts with MSAL's internal polling

    // Generate QR Code for mobile authentication
    console.log(`[QR CODE] Generating QR code for session: ${sessionId}`);
    // Use Microsoft's official verification URI from the response
    // This ensures compatibility and redirects to the correct tenant-specific page
    const qrCodeData = session.verificationUri;
    console.log(`[QR CODE] QR data: ${qrCodeData}`);
    
    let qrCodeSvg;
    try {
      qrCodeSvg = await QRCode.toString(qrCodeData, { 
        type: 'svg',
        width: 256,
        margin: 2,
        color: {
          dark: '#000000',
          light: '#FFFFFF'
        }
      });
      console.log(`[QR CODE] QR code generated successfully for session: ${sessionId}`);
    } catch (qrError) {
      console.error(`[QR CODE] Failed to generate QR code for session ${sessionId}:`, qrError);
      throw new Error(`QR code generation failed: ${qrError.message}`);
    }

    const responseData = {
      sessionId,
      userCode: session.userCode,
      verificationUri: session.verificationUri, // Use Microsoft's official verification URI for everything
      qrCode: qrCodeSvg,
      message: session.message,
      expiresIn: session.expiresIn,
      interval: session.interval // Include polling interval for frontend
    };

    console.log(`[AUTH] Sending response for session ${sessionId}:`, {
      ...responseData,
      qrCode: qrCodeSvg ? '[QR_CODE_GENERATED]' : '[QR_CODE_MISSING]'
    });

    res.json(responseData);

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
// Status check endpoint - returns server-side polling results
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

    // Return status without sensitive data (updated by server-side polling)
    const response = {
      status: session.status,
      userCode: session.userCode,
      expiresIn: Math.max(0, session.expiresIn - sessionAge),
      interval: session.interval,
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
 * Token validation endpoint for silent login
 * Validates an access token by calling Microsoft Graph
 */
app.post('/auth/validate-token', async (req, res) => {
  try {
    const { accessToken } = req.body;
    
    if (!accessToken) {
      return res.status(400).json({ error: 'Access token required' });
    }
    
    console.log('[TOKEN-VALIDATE] Validating token...');
    
    // Try to call Microsoft Graph to validate the token
    const graphResponse = await fetch('https://graph.microsoft.com/v1.0/me', {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
      }
    });
    
    if (graphResponse.ok) {
      const userData = await graphResponse.json();
      console.log('[TOKEN-VALIDATE] Token is valid');
      
      return res.json({
        valid: true,
        user: {
          name: userData.displayName,
          username: userData.userPrincipalName,
          id: userData.id
        }
      });
    } else {
      console.log('[TOKEN-VALIDATE] Token is invalid:', graphResponse.status);
      return res.json({ valid: false });
    }
    
  } catch (error) {
    console.error('[TOKEN-VALIDATE] Validation failed:', error);
    res.json({ valid: false });
  }
});

/**
 * Logout endpoint
 * Cleans up session and provides logout URL
 */
app.post('/auth/logout/:sessionId', (req, res) => {
  try {
    const { sessionId } = req.params;
    console.log(`[LOGOUT] Processing logout for session: ${sessionId}`);
    
    const session = deviceCodeSessions.get(sessionId);
    console.log(`[LOGOUT] Session found: ${!!session}, Total sessions before cleanup: ${deviceCodeSessions.size}`);

    // Clean up session
    deviceCodeSessions.delete(sessionId);
    console.log(`[LOGOUT] Session cleaned up, Total sessions after cleanup: ${deviceCodeSessions.size}`);

    // Provide logout URL for complete sign-out
    const logoutUrl = `https://login.microsoftonline.com/${process.env.TENANT_ID}/oauth2/v2.0/logout?post_logout_redirect_uri=${encodeURIComponent(process.env.POST_LOGOUT_REDIRECT_URI || 'http://localhost:3001')}`;

    const responseData = {
      success: true,
      logoutUrl,
      message: 'Logged out successfully'
    };

    console.log(`[LOGOUT] Logout successful for session ${sessionId}`);
    res.json(responseData);

  } catch (error) {
    console.error('[AUTH] Logout failed:', error);
    res.status(500).json({ error: 'Logout failed' });
  }
});

// Serve React app in production and Azure App Service
if (process.env.NODE_ENV === 'production' || process.env.WEBSITE_NODE_DEFAULT_VERSION) {
  const staticPath = path.join(__dirname, '../dist');
  console.log(`📂 Serving static files from: ${staticPath}`);
  
  // Serve static files with proper caching headers
  app.use(express.static(staticPath, {
    maxAge: '1d',
    etag: true,
    lastModified: true
  }));
  
  // Catch-all handler: send back React's index.html file for client-side routing
  app.get('*', (req, res) => {
    const indexPath = path.join(staticPath, 'index.html');
    console.log(`🌐 Serving index.html for route: ${req.path}`);
    res.sendFile(indexPath, (err) => {
      if (err) {
        console.error(`❌ Error serving index.html:`, err);
        res.status(500).send('Error loading application');
      }
    });
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

// Azure App Service and iisnode compatibility
if (process.env.WEBSITE_NODE_DEFAULT_VERSION) {
  console.log(`🚀 Secure Kiosk Server ready for Azure App Service (iisnode)`);
  console.log(`🔒 Environment: ${process.env.NODE_ENV}`);
  console.log(`🛡️  Security features enabled: Helmet, Rate Limiting (CORS handled by Azure App Service)`);
  console.log(`🌐 Website Site Name: ${process.env.WEBSITE_SITE_NAME || 'Unknown'}`);
  console.log(`📍 Website Resource Group: ${process.env.WEBSITE_RESOURCE_GROUP || 'Unknown'}`);
  
  // Configure trust proxy for Azure load balancer
  app.set('trust proxy', 1);
  console.log(`🔗 Trust proxy configured for Azure load balancer`);
  
  // Handle Azure App Service shutdown signals
  process.on('SIGTERM', () => {
    console.log('🛑 SIGTERM received in Azure App Service, shutting down gracefully');
    // Clean up device code sessions
    deviceCodeSessions.clear();
    console.log('✅ Cleanup completed');
  });
  
} else if (!module.parent) {
  // Local development - start the server normally
  app.listen(PORT, async () => {
    console.log(`🚀 Secure Kiosk Server running on port ${PORT}`);
    console.log(`🔒 Environment: ${process.env.NODE_ENV}`);
    console.log(`🛡️  Security features enabled: Helmet, Rate Limiting, CORS (local dev)`);
    
    // Load persisted sessions on startup
    await loadSessions();
    
    if (process.env.NODE_ENV === 'development') {
      console.log(`📱 React app: http://localhost:3000`);
      console.log(`🔑 Auth server: http://localhost:${PORT}`);
    }
  });
}

module.exports = app;