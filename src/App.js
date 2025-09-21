import React, { useState, useEffect } from 'react';
import axios from 'axios';

/**
 * Secure Kiosk React App with Entra ID Authentication
 * 
 * Features:
 * - Device Code Flow with PKCE for strongest security
 * - QR Code authentication for kiosk scenarios
 * - Passkey support through Entra ID
 * - Automatic token refresh and session management
 * - Secure API integration
 */

// API Configuration
const API_BASE_URL = process.env.NODE_ENV === 'production' 
  ? window.location.origin 
  : 'http://localhost:3001';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json'
  }
});

function App() {
  // Authentication State
  const [authState, setAuthState] = useState('unauthenticated'); // unauthenticated, authenticating, authenticated, error
  const [sessionId, setSessionId] = useState(null);
  const [user, setUser] = useState(null);
  const [authData, setAuthData] = useState(null);
  const [error, setError] = useState(null);

  // App State
  const [count, setCount] = useState(0);
  const [message, setMessage] = useState('Welcome to Secure Kiosk!');
  const [userProfile, setUserProfile] = useState(null);

  // Polling for authentication status
  useEffect(() => {
    let pollInterval;

    if (authState === 'authenticating' && sessionId) {
      pollInterval = setInterval(async () => {
        try {
          const response = await api.get(`/auth/device-code/status/${sessionId}`);
          const { status, user: authUser, error: authError } = response.data;

          if (status === 'completed') {
            setAuthState('authenticated');
            setUser(authUser);
            clearInterval(pollInterval);
            
            // Fetch user profile from Microsoft Graph
            fetchUserProfile();
          } else if (status === 'failed') {
            setAuthState('error');
            setError(authError || 'Authentication failed');
            clearInterval(pollInterval);
          } else if (status === 'expired') {
            setAuthState('error');
            setError('Authentication session expired. Please try again.');
            clearInterval(pollInterval);
          }
        } catch (err) {
          console.error('Polling error:', err);
          setError('Connection error during authentication');
          setAuthState('error');
          clearInterval(pollInterval);
        }
      }, 3000); // Poll every 3 seconds
    }

    return () => {
      if (pollInterval) {
        clearInterval(pollInterval);
      }
    };
  }, [authState, sessionId]);

  // Initialize authentication
  const startAuthentication = async () => {
    try {
      setAuthState('authenticating');
      setError(null);
      
      console.log('🔐 Starting device code authentication...');
      
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

      console.log('📱 Device code generated:', { userCode, verificationUri });
      
    } catch (error) {
      console.error('Authentication initialization failed:', error);
      setAuthState('error');
      setError(error.response?.data?.message || 'Failed to initialize authentication');
    }
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
      console.log('👤 User profile loaded:', profileResponse.data.displayName);
      
    } catch (error) {
      console.error('Failed to fetch user profile:', error);
      // Don't set error state - profile fetch failure shouldn't break the app
    }
  };

  // Logout function
  const logout = async () => {
    try {
      if (sessionId) {
        await api.post(`/auth/logout/${sessionId}`);
      }
      
      // Reset all state
      setAuthState('unauthenticated');
      setSessionId(null);
      setUser(null);
      setUserProfile(null);
      setAuthData(null);
      setError(null);
      setMessage('Welcome to Secure Kiosk!');
      setCount(0);
      
      console.log('🔓 Logged out successfully');
      
    } catch (error) {
      console.error('Logout failed:', error);
      // Force reset even if logout API fails
      setAuthState('unauthenticated');
      setSessionId(null);
      setUser(null);
      setUserProfile(null);
      setAuthData(null);
      setError(null);
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

  // Render authentication screen
  if (authState === 'unauthenticated') {
    return (
      <div className="app">
        <header className="app-header">
          <h1>🔐 Secure Kiosk</h1>
          <p className="message">Enterprise-Grade Authentication</p>
        </header>
        
        <main className="app-main">
          <div className="auth-section">
            <h2>Sign In Required</h2>
            <p>This kiosk requires authentication using your mobile device with passkey support.</p>
            
            <div className="security-features">
              <h3>🛡️ Security Features</h3>
              <ul>
                <li>✅ PKCE (Proof Key for Code Exchange)</li>
                <li>✅ Device Code Flow for kiosks</li>
                <li>✅ Passkey authentication support</li>
                <li>✅ Microsoft Entra ID protection</li>
                <li>✅ QR code mobile sign-in</li>
              </ul>
            </div>
            
            <button onClick={startAuthentication} className="btn btn-primary btn-large">
              🔑 Start Secure Sign-In
            </button>
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
            
            <button onClick={logout} className="btn btn-secondary">
              Cancel Authentication
            </button>
          </div>
        </main>
      </div>
    );
  }

  // Render error state
  if (authState === 'error') {
    return (
      <div className="app">
        <header className="app-header">
          <h1>❌ Authentication Error</h1>
          <p className="message">Please try again</p>
        </header>
        
        <main className="app-main">
          <div className="error-section">
            <h2>Authentication Failed</h2>
            <p className="error-message">{error}</p>
            
            <div className="button-group">
              <button onClick={startAuthentication} className="btn btn-primary">
                Try Again
              </button>
              <button onClick={() => setAuthState('unauthenticated')} className="btn btn-secondary">
                Back
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