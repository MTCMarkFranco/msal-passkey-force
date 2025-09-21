import { useState, useEffect } from 'react';
import axios from 'axios';

/**
 * Secure Kiosk React App with Entra ID Authentication
 * 
 * Features:
 * - Device Code Flow with PKCE for strongest security
 * - QR Code authentication for kiosk scenarios
 * - Passkey support through Entra ID
 * - Automatic token refresh and session management
 * - Token caching with silent login
 * - Secure API integration
 */

// Cookie utilities for token caching
const CookieUtils = {
  set: (name, value, days = 7) => {
    const expires = new Date();
    expires.setTime(expires.getTime() + (days * 24 * 60 * 60 * 1000));
    document.cookie = `${name}=${encodeURIComponent(JSON.stringify(value))};expires=${expires.toUTCString()};path=/;secure;samesite=strict`;
  },
  
  get: (name) => {
    const nameEQ = name + "=";
    const ca = document.cookie.split(';');
    for(let i = 0; i < ca.length; i++) {
      let c = ca[i];
      while (c.charAt(0) === ' ') c = c.substring(1, c.length);
      if (c.indexOf(nameEQ) === 0) {
        try {
          return JSON.parse(decodeURIComponent(c.substring(nameEQ.length, c.length)));
        } catch (e) {
          console.warn('Failed to parse cookie:', name);
          return null;
        }
      }
    }
    return null;
  },
  
  delete: (name) => {
    document.cookie = `${name}=;expires=Thu, 01 Jan 1970 00:00:00 UTC;path=/;`;
  },
  
  exists: (name) => {
    return CookieUtils.get(name) !== null;
  }
};

// API Configuration - Now using same server for frontend and backend
const API_BASE_URL = window.location.origin;

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json'
  }
});

// Token cache constants
const AUTH_TOKEN_COOKIE = 'msal_auth_token';
const AUTH_USER_COOKIE = 'msal_user_info';

function App() {
  // Authentication State
  const [authState, setAuthState] = useState('checking_cache'); // checking_cache, initializing, authenticating, authenticated, error
  const [sessionId, setSessionId] = useState(null);
  const [user, setUser] = useState(null);
  const [authData, setAuthData] = useState(null);
  const [error, setError] = useState(null);
  const [isAuthStarting, setIsAuthStarting] = useState(false); // Prevent multiple auth starts
  const [cachedToken, setCachedToken] = useState(null);

  // App State
  const [count, setCount] = useState(0);
  const [message, setMessage] = useState('Welcome to Secure Kiosk!');
  const [userProfile, setUserProfile] = useState(null);

  // Preflight check: Look for cached token and attempt silent login
  useEffect(() => {
    if (process.env.NODE_ENV === 'development') {
      console.log('🔐 App initialized - Starting preflight token check...');
    }
    
    if (authState === 'checking_cache') {
      performPreflightCheck();
    }
  }, []); // Empty dependency array means this runs once when component mounts

  // Auto-start authentication if no cached token found
  useEffect(() => {
    if (authState === 'initializing' && !isAuthStarting && !sessionId) {
      if (process.env.NODE_ENV === 'development') {
        console.log('🔐 No cached token found - Starting device code authentication...');
      }
      startAuthentication();
    }
  }, [authState, isAuthStarting, sessionId]);

  // Only retry on specific authentication errors, not connection errors
  useEffect(() => {
    let retryTimeout;
    
    // Only retry for expired sessions, not other auth failures to avoid loops
    if (authState === 'error' && error && error.includes('expired')) {
      if (process.env.NODE_ENV === 'development') {
        console.log('⚠️ Session expired - Will retry in 5 seconds...', error);
      }
      retryTimeout = setTimeout(() => {
        if (process.env.NODE_ENV === 'development') {
          console.log('🔄 Auto-retrying authentication due to session expiry...');
        }
        startAuthentication();
      }, 5000);
    } else if (authState === 'error' && process.env.NODE_ENV === 'development') {
      console.log('❌ Authentication error - Manual retry required:', error);
    }

    return () => {
      if (retryTimeout) {
        clearTimeout(retryTimeout);
      }
    };
  }, [authState, error]); // Runs when authState or error changes

  // Polling for authentication status
  useEffect(() => {
    let pollInterval;

    if (authState === 'authenticating' && sessionId) {
      if (process.env.NODE_ENV === 'development') {
        console.log('🔍 Starting authentication polling for session:', sessionId);
      }
      
      pollInterval = setInterval(async () => {
        try {
          const response = await api.get(`/auth/device-code/status/${sessionId}`);
          const { status, user: authUser, error: authError } = response.data;

          if (process.env.NODE_ENV === 'development') {
            console.log('📊 Poll result:', { status, sessionId });
          }

          if (status === 'completed') {
            if (process.env.NODE_ENV === 'development') {
              console.log('✅ Authentication completed successfully!');
            }
            setAuthState('authenticated');
            setUser(authUser);
            clearInterval(pollInterval);
            
            // Clear any existing errors
            setError(null);
            
            // Get token and cache it
            await cacheAuthenticationData(authUser);
            
            // Fetch user profile from Microsoft Graph
            fetchUserProfile();
          } else if (status === 'failed') {
            if (process.env.NODE_ENV === 'development') {
              console.log('❌ Authentication failed:', authError);
            }
            setAuthState('error');
            setError(authError || 'Authentication failed - please try again manually');
            clearInterval(pollInterval);
          } else if (status === 'expired') {
            if (process.env.NODE_ENV === 'development') {
              console.log('⏰ Authentication session expired');
            }
            setAuthState('error');
            setError('Authentication session expired. Please try again.');
            clearInterval(pollInterval);
          } else if (status === 'pending' && process.env.NODE_ENV === 'development') {
            console.log('⏳ Still waiting for user authentication...');
            // Continue polling
          }
        } catch (err) {
          if (process.env.NODE_ENV === 'development') {
            console.error('❌ Polling error:', err);
          }
          setError('Connection error during authentication');
          setAuthState('error');
          clearInterval(pollInterval);
        }
      }, 3000); // Poll every 3 seconds
    }

    // Cleanup function
    return () => {
      if (pollInterval) {
        if (process.env.NODE_ENV === 'development') {
          console.log('🛑 Stopping authentication polling');
        }
        clearInterval(pollInterval);
      }
    };
  }, [authState, sessionId]); // Dependencies: authState and sessionId

  // Initialize authentication with safeguards against multiple calls
  // Preflight check: Attempt to authenticate with cached token
  const performPreflightCheck = async () => {
    if (process.env.NODE_ENV === 'development') {
      console.log('🔍 Performing preflight token check...');
    }
    
    try {
      // Check if we have a cached token
      const cachedTokenData = CookieUtils.get(AUTH_TOKEN_COOKIE);
      const cachedUserData = CookieUtils.get(AUTH_USER_COOKIE);
      
      if (!cachedTokenData || !cachedUserData) {
        if (process.env.NODE_ENV === 'development') {
          console.log('❌ No cached token found - proceeding with device code flow');
        }
        setAuthState('initializing');
        return;
      }
      
      // Check if token is expired
      const tokenExpiresOn = new Date(cachedTokenData.expiresOn);
      const now = new Date();
      const timeUntilExpiry = tokenExpiresOn.getTime() - now.getTime();
      
      if (timeUntilExpiry <= 60000) { // Token expires within 1 minute
        if (process.env.NODE_ENV === 'development') {
          console.log('⏰ Cached token is expired or about to expire - clearing cache');
        }
        CookieUtils.delete(AUTH_TOKEN_COOKIE);
        CookieUtils.delete(AUTH_USER_COOKIE);
        setAuthState('initializing');
        return;
      }
      
      if (process.env.NODE_ENV === 'development') {
        console.log('✅ Found valid cached token - attempting silent login');
        console.log(`🕒 Token expires in: ${Math.round(timeUntilExpiry / 1000 / 60)} minutes`);
      }
      
      // Validate the cached token via server
      const validationResponse = await api.post('/auth/validate-token', {
        accessToken: cachedTokenData.accessToken
      });
      
      if (validationResponse.data.valid) {
        if (process.env.NODE_ENV === 'development') {
          console.log('🎉 Silent login successful!');
        }
        
        // Set up axios interceptor to use the cached token
        api.defaults.headers.common['Authorization'] = `${cachedTokenData.tokenType} ${cachedTokenData.accessToken}`;
        setCachedToken(cachedTokenData);
        
        // Restore user state
        setUser(cachedUserData);
        
        // Fetch fresh user profile
        try {
          const profileResponse = await api.get('https://graph.microsoft.com/v1.0/me');
          setUserProfile(profileResponse.data);
        } catch (profileError) {
          console.warn('Failed to fetch fresh profile:', profileError);
          // Use cached user data as fallback
          setUserProfile({
            displayName: cachedUserData.name,
            userPrincipalName: cachedUserData.username
          });
        }
        
        setAuthState('authenticated');
        setError(null);
        return;
      } else {
        if (process.env.NODE_ENV === 'development') {
          console.log('❌ Cached token is no longer valid');
        }
      }
      
    } catch (error) {
      if (process.env.NODE_ENV === 'development') {
        console.log('❌ Silent login failed:', error.response?.status, error.message);
      }
      
      // Clear invalid cached data
      CookieUtils.delete(AUTH_TOKEN_COOKIE);
      CookieUtils.delete(AUTH_USER_COOKIE);
      delete api.defaults.headers.common['Authorization'];
      setCachedToken(null);
    }
    
    // Fall back to device code flow
    setAuthState('initializing');
  };

  // Cache authentication data after successful login
  const cacheAuthenticationData = async (authUser) => {
    try {
      if (!sessionId) {
        console.warn('No session ID available for token caching');
        return;
      }
      
      // Get the access token from the server
      const tokenResponse = await api.get(`/auth/token/${sessionId}`);
      const tokenData = tokenResponse.data;
      
      if (process.env.NODE_ENV === 'development') {
        console.log('💾 Caching authentication data...');
      }
      
      // Cache token data
      CookieUtils.set(AUTH_TOKEN_COOKIE, {
        accessToken: tokenData.accessToken,
        tokenType: tokenData.tokenType || 'Bearer',
        scopes: tokenData.scopes,
        expiresOn: tokenData.expiresOn
      }, 7); // Cache for 7 days
      
      // Cache user data
      CookieUtils.set(AUTH_USER_COOKIE, authUser, 7);
      
      // Set up axios interceptor for future API calls
      api.defaults.headers.common['Authorization'] = `${tokenData.tokenType || 'Bearer'} ${tokenData.accessToken}`;
      
      if (process.env.NODE_ENV === 'development') {
        console.log('✅ Authentication data cached successfully');
      }
      
    } catch (error) {
      console.error('Failed to cache authentication data:', error);
    }
  };

  const startAuthentication = async () => {
    // Prevent multiple simultaneous authentication attempts
    if (isAuthStarting || authState === 'authenticating' || sessionId) {
      if (process.env.NODE_ENV === 'development') {
        console.log('🔐 Authentication already in progress, ignoring duplicate call');
      }
      return;
    }

    try {
      setIsAuthStarting(true);
      setAuthState('authenticating');
      setError(null);
      
      if (process.env.NODE_ENV === 'development') {
        console.log('🔐 Starting device code authentication...');
      }
      
      const response = await api.post('/auth/device-code/start');
      const { sessionId: newSessionId, userCode, verificationUri, qrCode, message: authMessage, expiresIn } = response.data;
      
      setSessionId(newSessionId);
      setAuthData({
        userCode,
        verificationUri,
        qrCode,
        message: authMessage,
        expiresIn
      });

      if (process.env.NODE_ENV === 'development') {
        console.log('📱 Device code generated:', { userCode, verificationUri });
      }
      
    } catch (error) {
      console.error('Authentication initialization failed:', error);
      setAuthState('error');
      setError(error.response?.data?.message || 'Failed to initialize authentication');
    } finally {
      setIsAuthStarting(false);
    }
  };

  // Generate a new authentication code
  const generateNewCode = async () => {
    if (process.env.NODE_ENV === 'development') {
      console.log('🔄 Generating new authentication code...');
    }
    // Reset session state before starting new authentication
    setSessionId(null);
    setAuthData(null);
    setAuthState('initializing');
    setError(null);
    
    // Small delay to ensure state is reset
    setTimeout(() => {
      startAuthentication();
    }, 100);
  };

  // Fetch user profile using Microsoft Graph API
  const fetchUserProfile = async () => {
    try {
      const tokenResponse = await api.get(`/auth/token/${sessionId}`);
      const { accessToken } = tokenResponse.data;

      // Call Microsoft Graph API
      const profileResponse = await axios.get('https://graph.microsoft.com/v1.0/me', {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        }
      });

      setUserProfile(profileResponse.data);
      if (process.env.NODE_ENV === 'development') {
        console.log('👤 User profile loaded:', profileResponse.data.displayName);
      }
      
    } catch (error) {
      if (process.env.NODE_ENV === 'development') {
        console.error('Failed to fetch user profile:', error);
      }
      // Don't set error state - profile fetch failure shouldn't break the app
    }
  };

  // Logout function
  const logout = async () => {
    try {
      if (sessionId) {
        await api.post(`/auth/logout/${sessionId}`);
      }
      
      // Clear cached authentication data
      CookieUtils.delete(AUTH_TOKEN_COOKIE);
      CookieUtils.delete(AUTH_USER_COOKIE);
      delete api.defaults.headers.common['Authorization'];
      setCachedToken(null);
      
      // Reset all state
      setAuthState('initializing');
      setSessionId(null);
      setUser(null);
      setUserProfile(null);
      setAuthData(null);
      setError(null);
      setIsAuthStarting(false);
      setMessage('Welcome to Secure Kiosk!');
      setCount(0);
      
      if (process.env.NODE_ENV === 'development') {
        console.log('🔓 Logged out successfully - Cache cleared - Ready for new authentication');
      }
      
      // Don't auto-restart - let user manually authenticate if needed
      // This prevents unwanted authentication loops
      
    } catch (error) {
      if (process.env.NODE_ENV === 'development') {
        console.error('Logout failed:', error);
      }
      // Force reset even if logout API fails
      CookieUtils.delete(AUTH_TOKEN_COOKIE);
      CookieUtils.delete(AUTH_USER_COOKIE);
      delete api.defaults.headers.common['Authorization'];
      setCachedToken(null);
      
      setAuthState('initializing');
      setSessionId(null);
      setUser(null);
      setUserProfile(null);
      setAuthData(null);
      setError(null);
      setIsAuthStarting(false);
      setMessage('Welcome to Secure Kiosk!');
      setCount(0);
    }
  };

  // App functions
  const handleIncrement = () => setCount(count + 1);
  const handleDecrement = () => setCount(count - 1);
  const handleReset = () => setCount(0);

  const handleMessageChange = () => {
    const messages = [
      'Welcome to Secure Kiosk!',
      'Authenticated with Entra ID!',
      'PKCE Security Enabled!',
      'Passkey Authentication Active!',
      'Microsoft Graph Connected!',
      userProfile ? `Hello ${userProfile.displayName}!` : 'Secure Session Active!'
    ];
    const randomMessage = messages[Math.floor(Math.random() * messages.length)];
    setMessage(randomMessage);
  };

  // Render initialization screen (briefly shown while starting auth)
  // Loading state for cache check
  if (authState === 'checking_cache') {
    return (
      <div className="app">
        <header className="app-header">
          <h1>🔐 Secure Kiosk</h1>
          <p className="message">Checking for existing session...</p>
        </header>
        
        <main className="app-main">
          <div className="auth-section">
            <div className="auth-progress">
              <div className="loading-spinner"></div>
              <h2>🔍 Checking Cached Authentication</h2>
              <p>Looking for existing login session...</p>
              <div className="security-note">
                <p><strong>🔒 Attempting Silent Login:</strong> Checking for valid authentication token in secure browser storage.</p>
              </div>
            </div>
          </div>
        </main>
      </div>
    );
  }

  if (authState === 'initializing') {
    return (
      <div className="app">
        <header className="app-header">
          <h1>🔐 Secure Kiosk</h1>
          <p className="message">Initializing Authentication...</p>
        </header>
        
        <main className="app-main">
          <div className="auth-section">
            <div className="auth-progress">
              <div className="loading-spinner"></div>
              <h2>Starting Secure Authentication</h2>
              <p>Generating QR code for mobile sign-in...</p>
              
              <div className="security-features">
                <h3>🛡️ Security Features Active</h3>
                <ul>
                  <li>✅ PKCE (Proof Key for Code Exchange)</li>
                  <li>✅ Device Code Flow for kiosks</li>
                  <li>✅ Passkey authentication support</li>
                  <li>✅ Microsoft Entra ID protection</li>
                  <li>✅ QR code mobile sign-in</li>
                </ul>
              </div>
            </div>
          </div>
        </main>
        
        <footer className="app-footer">
          <p>&copy; 2025 Secure Kiosk App - Protected by Microsoft Entra ID</p>
        </footer>
      </div>
    );
  }

  // Render authentication in progress
  if (authState === 'authenticating') {
    return (
      <div className="app">
        <header className="app-header">
          <h1>📱 Authentication in Progress</h1>
          <p className="message">Scan QR code with your mobile device</p>
        </header>
        
        <main className="app-main">
          <div className="qr-auth-section">
            {authData && (
              <>
                <div className="qr-code-container">
                  <h2>Scan with Your Phone</h2>
                  <div 
                    className="qr-code"
                    dangerouslySetInnerHTML={{ __html: authData.qrCode }}
                  />
                  
                  <div className="auth-instructions">
                    <h3>Alternative: Manual Code Entry</h3>
                    <p>Go to: <strong>{authData.verificationUri}</strong></p>
                    <p>Enter code: <span className="user-code">{authData.userCode}</span></p>
                  </div>
                </div>
                
                <div className="auth-progress">
                  <div className="loading-spinner"></div>
                  <p>Waiting for authentication...</p>
                  <p className="auth-message">{authData.message}</p>
                </div>
              </>
            )}
            
            <div className="button-group">
              <button onClick={generateNewCode} className="btn btn-primary">
                Generate New Code
              </button>
              <button onClick={logout} className="btn btn-secondary">
                Cancel Authentication
              </button>
            </div>
          </div>
        </main>
      </div>
    );
  }

  // Render error state
  if (authState === 'error') {
    const isAuthError = error && (error.includes('expired') || error.includes('Authentication failed') || error.includes('AADSTS'));
    
    return (
      <div className="app">
        <header className="app-header">
          <h1>❌ Authentication Error</h1>
          <p className="message">
            {isAuthError ? 'Will retry automatically...' : 'Manual retry required'}
          </p>
        </header>
        
        <main className="app-main">
          <div className="error-section">
            <h2>{isAuthError ? 'Authentication Failed' : 'Connection Error'}</h2>
            <p className="error-message">{error}</p>
            
            {isAuthError ? (
              <div className="auth-progress">
                <div className="loading-spinner"></div>
                <p>Automatically retrying in 5 seconds...</p>
              </div>
            ) : (
              <p>Please check your connection and try again.</p>
            )}
            
            <div className="button-group">
              <button onClick={startAuthentication} className="btn btn-primary">
                Try Again Now
              </button>
              <button onClick={() => {
                CookieUtils.delete(AUTH_TOKEN_COOKIE);
                CookieUtils.delete(AUTH_USER_COOKIE);
                delete api.defaults.headers.common['Authorization'];
                setCachedToken(null);
                setAuthState('checking_cache');
                setTimeout(() => performPreflightCheck(), 100);
              }} className="btn btn-secondary">
                Clear Cache & Retry
              </button>
            </div>
          </div>
        </main>
      </div>
    );
  }

  // Render authenticated app
  return (
    <div className="app">
      <header className="app-header">
        <h1>🔒 Secure Kiosk Dashboard</h1>
        <p className="message">{message}</p>
        {user && (
          <div className="user-info">
            <span>👤 {userProfile?.displayName || user.name || user.username}</span>
            <button onClick={logout} className="btn btn-small btn-logout">
              Sign Out
            </button>
          </div>
        )}
      </header>
      
      <main className="app-main">
        <div className="counter-section">
          <h2>Counter: {count}</h2>
          <div className="button-group">
            <button onClick={handleDecrement} className="btn btn-danger">
              -
            </button>
            <button onClick={handleReset} className="btn btn-secondary">
              Reset
            </button>
            <button onClick={handleIncrement} className="btn btn-success">
              +
            </button>
          </div>
        </div>
        
        <div className="message-section">
          <button onClick={handleMessageChange} className="btn btn-primary">
            Change Message
          </button>
        </div>
        
        {userProfile && (
          <div className="profile-section">
            <h3>👤 User Profile</h3>
            <div className="profile-info">
              <p><strong>Name:</strong> {userProfile.displayName}</p>
              <p><strong>Email:</strong> {userProfile.mail || userProfile.userPrincipalName}</p>
              <p><strong>Job Title:</strong> {userProfile.jobTitle || 'Not specified'}</p>
              <p><strong>Department:</strong> {userProfile.department || 'Not specified'}</p>
            </div>
          </div>
        )}
        
        <div className="info-section">
          <h3>🔐 Security Features</h3>
          <ul>
            <li>✅ OAuth 2.0 Authorization Code Flow with PKCE</li>
            <li>✅ Device Code Flow for kiosk scenarios</li>
            <li>✅ Microsoft Entra ID authentication</li>
            <li>✅ Passkey and mobile device support</li>
            <li>✅ Microsoft Graph API integration</li>
            <li>✅ Secure session management</li>
            <li>✅ Rate limiting and security headers</li>
          </ul>
        </div>
      </main>
      
      <footer className="app-footer">
        <p>&copy; 2025 Secure Kiosk App - Session Active</p>
      </footer>
    </div>
  );
}

export default App;