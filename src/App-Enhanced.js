import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
  startRegistration,
  startAuthentication,
  browserSupportsWebAuthn,
  platformAuthenticatorIsAvailable
} from '@simplewebauthn/browser';

const api = axios.create({
  baseURL: window.location.origin,
  timeout: 30000,
  withCredentials: true
});

function App() {
  const [authState, setAuthState] = useState('loading');
  const [user, setUser] = useState(null);
  const [entraUser, setEntraUser] = useState(null);
  const [error, setError] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isRegistering, setIsRegistering] = useState(false);
  const [showRegistration, setShowRegistration] = useState(false);
  const [showEntraIdLogin, setShowEntraIdLogin] = useState(false);
  const [authMode, setAuthMode] = useState('standalone'); // 'standalone' or 'entra-id'
  const [registrationForm, setRegistrationForm] = useState({ username: '', displayName: '', useEntraId: false });
  const [webAuthnSupport, setWebAuthnSupport] = useState({ supported: false, platformAvailable: false });
  const [users, setUsers] = useState([]);
  const [entraConfig, setEntraConfig] = useState(null);

  useEffect(() => {
    const init = async () => {
      try {
        // Check WebAuthn support
        const supported = browserSupportsWebAuthn();
        let platformAvailable = false;
        
        try {
          platformAvailable = await platformAuthenticatorIsAvailable();
        } catch (e) {
          console.warn('Platform auth check failed:', e);
        }
        
        setWebAuthnSupport({ supported, platformAvailable });
        
        if (!supported) {
          setError('WebAuthn not supported in this browser');
          setAuthState('error');
          return;
        }

        // Load Entra ID configuration
        try {
          const configResponse = await api.get('/api/auth/entra-config');
          setEntraConfig(configResponse.data);
        } catch (e) {
          console.warn('Entra ID config not available:', e);
        }
        
        // Check existing session
        try {
          const response = await api.get('/api/auth/session');
          if (response.data?.user) {
            setUser(response.data.user);
            setAuthState('authenticated');
          } else {
            setAuthState('unauthenticated');
          }
        } catch (e) {
          setAuthState('unauthenticated');
        }

        // Load users list
        await loadUsers();
      } catch (error) {
        console.error('Initialization error:', error);
        setError('Failed to initialize application');
        setAuthState('error');
      }
    };

    init();
  }, []);

  const loadUsers = async () => {
    try {
      const response = await api.get('/api/users');
      setUsers(response.data);
    } catch (error) {
      console.warn('Could not load users:', error);
    }
  };

  // Entra ID Authentication Flow
  const handleEntraIdLogin = async () => {
    if (!entraConfig) {
      setError('Entra ID not configured');
      return;
    }

    try {
      setIsLoading(true);
      setError(null);

      // Create Microsoft Authentication Library (MSAL) instance
      const msalConfig = {
        auth: {
          clientId: entraConfig.clientId,
          authority: entraConfig.authority,
          redirectUri: entraConfig.redirectUri
        }
      };

      // Simulate MSAL login (in a real app, you'd use @azure/msal-browser)
      console.log('Redirecting to Entra ID login...');
      
      // For demo purposes, we'll simulate getting a token
      // In reality, this would be handled by MSAL.js
      const mockAccessToken = await simulateEntraIdLogin();
      
      if (mockAccessToken) {
        await validateEntraIdToken(mockAccessToken);
      }
    } catch (error) {
      console.error('Entra ID login error:', error);
      setError(`Entra ID login failed: ${error.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  // Simulate Entra ID login (replace with real MSAL implementation)
  const simulateEntraIdLogin = async () => {
    return new Promise((resolve) => {
      // In a real implementation, this would be handled by MSAL.js
      const mockUser = prompt('Enter your Entra ID email (e.g., user@MngEnvMCAP490549.onmicrosoft.com):');
      if (mockUser && mockUser.includes('@MngEnvMCAP490549.onmicrosoft.com')) {
        // Create a mock JWT token for demo purposes
        const mockPayload = {
          iss: 'https://sts.windows.net/tenant-id/',
          aud: entraConfig.clientId,
          sub: 'mock-user-id-' + Date.now(),
          oid: 'mock-object-id-' + Date.now(),
          tid: 'MngEnvMCAP490549.onmicrosoft.com',
          upn: mockUser,
          name: mockUser.split('@')[0],
          email: mockUser,
          exp: Math.floor(Date.now() / 1000) + 3600,
          iat: Math.floor(Date.now() / 1000)
        };
        const mockToken = btoa(JSON.stringify({ typ: 'JWT' })) + '.' + 
                          btoa(JSON.stringify(mockPayload)) + '.' + 
                          btoa('mock-signature');
        resolve(mockToken);
      } else {
        resolve(null);
      }
    });
  };

  const validateEntraIdToken = async (accessToken) => {
    try {
      const response = await api.post('/api/auth/entra-validate', { accessToken });
      
      if (response.data.validated) {
        setEntraUser(response.data.user);
        setAuthMode('entra-id');
        
        if (response.data.hasPasskeys) {
          // User has passkeys, show authentication option
          setAuthState('entra-authenticated');
        } else {
          // User needs to register passkeys
          setShowRegistration(true);
          setRegistrationForm({
            username: response.data.user.userPrincipalName,
            displayName: response.data.user.displayName,
            useEntraId: true
          });
        }
      }
    } catch (error) {
      throw new Error(`Token validation failed: ${error.response?.data?.error || error.message}`);
    }
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    
    if (!registrationForm.username.trim()) {
      setError('Username is required');
      return;
    }

    try {
      setIsRegistering(true);
      setError(null);

      console.log('Starting passkey registration...');

      // Generate registration options
      const optionsResponse = await api.post('/api/webauthn/generate-registration-options', {
        username: registrationForm.username,
        displayName: registrationForm.displayName || registrationForm.username,
        useEntraId: registrationForm.useEntraId || authMode === 'entra-id'
      });

      console.log('Registration options received:', {
        enterpriseMode: optionsResponse.data.enterpriseMode,
        userVerification: optionsResponse.data.authenticatorSelection?.userVerification
      });

      // Start WebAuthn registration
      const registrationResponse = await startRegistration(optionsResponse.data);
      console.log('WebAuthn registration completed');

      // Verify registration
      const verificationResponse = await api.post('/api/webauthn/verify-registration', registrationResponse);

      if (verificationResponse.data.verified) {
        console.log('Passkey registration successful!');
        setShowRegistration(false);
        setRegistrationForm({ username: '', displayName: '', useEntraId: false });
        
        // Refresh users list
        await loadUsers();
        
        if (authMode === 'entra-id') {
          setAuthState('entra-authenticated');
        } else {
          setAuthState('unauthenticated');
        }

        // Show success message
        alert(`Passkey registered successfully!\\n\\nDevice: ${verificationResponse.data.passkeyInfo.deviceType}\\nEnterprise Mode: ${verificationResponse.data.passkeyInfo.enterpriseMode}\\nPasskeys: ${verificationResponse.data.userInfo.totalPasskeys}`);
      } else {
        throw new Error('Registration verification failed');
      }
    } catch (error) {
      console.error('Registration error:', error);
      
      if (error.name === 'NotAllowedError') {
        setError('Registration was cancelled or not allowed by the browser');
      } else if (error.name === 'InvalidStateError') {
        setError('This device already has a passkey for this account');
      } else {
        setError(`Registration failed: ${error.message || 'Unknown error'}`);
      }
    } finally {
      setIsRegistering(false);
    }
  };

  const handleAuthenticate = async () => {
    try {
      setIsLoading(true);
      setError(null);

      console.log('Starting passkey authentication...');

      // Generate authentication options
      const optionsResponse = await api.post('/api/webauthn/generate-authentication-options', {
        username: authMode === 'entra-id' ? entraUser?.userPrincipalName : undefined
      });

      console.log('Authentication options received');

      // Start WebAuthn authentication
      const authResponse = await startAuthentication(optionsResponse.data);
      console.log('WebAuthn authentication completed');

      // Verify authentication
      const verificationResponse = await api.post('/api/webauthn/verify-authentication', authResponse);

      if (verificationResponse.data.verified) {
        console.log('Authentication successful!');
        setUser(verificationResponse.data.user);
        setAuthState('authenticated');
        
        // Show success message
        alert(`Welcome back, ${verificationResponse.data.user.displayName}!`);
      } else {
        throw new Error('Authentication verification failed');
      }
    } catch (error) {
      console.error('Authentication error:', error);
      
      if (error.name === 'NotAllowedError') {
        setError('Authentication was cancelled or not allowed');
      } else if (error.response?.data?.requireRegistration) {
        setError('No passkey found. Please register a passkey first.');
        setShowRegistration(true);
      } else {
        setError(`Authentication failed: ${error.message || 'Unknown error'}`);
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleLogout = async () => {
    try {
      await api.post('/api/auth/logout');
      setUser(null);
      setEntraUser(null);
      setAuthState('unauthenticated');
      setAuthMode('standalone');
      setError(null);
    } catch (error) {
      console.error('Logout error:', error);
    }
  };

  const renderAuthenticationMethods = () => (
    <div className="auth-methods">
      <h2>Choose Authentication Method</h2>
      
      <div className="auth-method-card">
        <h3>🔐 Standalone Passkey</h3>
        <p>Create and use passkeys without organizational account</p>
        <button 
          onClick={() => {
            setAuthMode('standalone');
            setShowRegistration(true);
          }}
          className="button-primary"
        >
          Register Standalone Passkey
        </button>
        {users.length > 0 && (
          <button 
            onClick={handleAuthenticate}
            className="button-secondary"
            disabled={isLoading}
          >
            Sign In with Existing Passkey
          </button>
        )}
      </div>

      {entraConfig && (
        <div className="auth-method-card enterprise">
          <h3>🏢 Enterprise Authentication</h3>
          <p>Sign in with your MngEnvMCAP490549.onmicrosoft.com account</p>
          <button 
            onClick={handleEntraIdLogin}
            className="button-primary enterprise"
            disabled={isLoading}
          >
            {isLoading ? 'Connecting...' : 'Sign In with Entra ID'}
          </button>
        </div>
      )}
    </div>
  );

  if (authState === 'loading') {
    return <div className="loading">🔄 Loading...</div>;
  }

  if (authState === 'error') {
    return (
      <div className="error-container">
        <h2>⚠️ Error</h2>
        <p>{error}</p>
        <button onClick={() => window.location.reload()}>Reload Page</button>
      </div>
    );
  }

  if (authState === 'authenticated') {
    return (
      <div className="container">
        <div className="header">
          <h1>🔐 Secure Kiosk - Enterprise Edition</h1>
          <div className="user-info">
            <span>Welcome, {user.displayName || user.username}!</span>
            <button onClick={handleLogout} className="button-secondary">Logout</button>
          </div>
        </div>

        <div className="dashboard">
          <div className="stats-card">
            <h3>✅ Authenticated Successfully</h3>
            <p><strong>User:</strong> {user.username}</p>
            <p><strong>Display Name:</strong> {user.displayName}</p>
            <p><strong>Authentication Method:</strong> {authMode === 'entra-id' ? 'Enterprise (Entra ID + Passkey)' : 'Standalone Passkey'}</p>
            <p><strong>Session Active:</strong> ✓</p>
          </div>

          <div className="protected-content">
            <h3>🛡️ Protected Content</h3>
            <p>This content is only visible to authenticated users.</p>
            <p>Your passkey provides secure, passwordless authentication.</p>
          </div>
        </div>

        <div className="users-section">
          <h3>👥 Registered Users ({users.length})</h3>
          {users.length === 0 ? (
            <p>No users registered yet.</p>
          ) : (
            <div className="users-grid">
              {users.map(u => (
                <div key={u.id} className="user-card">
                  <strong>{u.displayName || u.username}</strong>
                  <small>{u.username}</small>
                  <span className="passkey-count">{u.authenticatorCount} passkey{u.authenticatorCount !== 1 ? 's' : ''}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    );
  }

  if (authState === 'entra-authenticated') {
    return (
      <div className="container">
        <div className="header">
          <h1>🏢 Enterprise Authentication</h1>
        </div>

        <div className="entra-success">
          <h2>✅ Entra ID Authentication Successful</h2>
          <div className="user-info-card">
            <p><strong>User:</strong> {entraUser.userPrincipalName}</p>
            <p><strong>Display Name:</strong> {entraUser.displayName}</p>
            <p><strong>Email:</strong> {entraUser.email}</p>
          </div>

          <div className="next-steps">
            <h3>🔐 Complete Authentication with Passkey</h3>
            <p>Use your registered passkey to complete secure authentication.</p>
            <button 
              onClick={handleAuthenticate}
              className="button-primary enterprise"
              disabled={isLoading}
            >
              {isLoading ? 'Authenticating...' : 'Authenticate with Passkey'}
            </button>
          </div>

          <button 
            onClick={() => {
              setEntraUser(null);
              setAuthState('unauthenticated');
            }}
            className="button-secondary"
          >
            Back to Login Options
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="container">
      <div className="header">
        <h1>🔐 Secure Kiosk - Enterprise Edition</h1>
        <div className="webauthn-support">
          <span className={webAuthnSupport.supported ? 'supported' : 'unsupported'}>
            WebAuthn: {webAuthnSupport.supported ? '✅ Supported' : '❌ Not Supported'}
          </span>
          {webAuthnSupport.supported && (
            <span className={webAuthnSupport.platformAvailable ? 'supported' : 'unsupported'}>
              Platform Auth: {webAuthnSupport.platformAvailable ? '✅ Available' : '⚠️ Limited'}
            </span>
          )}
        </div>
      </div>

      {error && (
        <div className="error">
          <strong>Error:</strong> {error}
          <button onClick={() => setError(null)}>×</button>
        </div>
      )}

      {!showRegistration && !showEntraIdLogin && renderAuthenticationMethods()}

      {showRegistration && (
        <div className="registration-form">
          <h2>{authMode === 'entra-id' ? '🏢 Register Enterprise Passkey' : '🔐 Register New Passkey'}</h2>
          
          {authMode === 'entra-id' && (
            <div className="enterprise-info">
              <p><strong>Entra ID User:</strong> {entraUser?.userPrincipalName}</p>
              <p><strong>Display Name:</strong> {entraUser?.displayName}</p>
              <p>Your passkey will be linked to your enterprise account.</p>
            </div>
          )}

          <form onSubmit={handleRegister}>
            {authMode !== 'entra-id' && (
              <>
                <input
                  type="email"
                  placeholder="Username (email)"
                  value={registrationForm.username}
                  onChange={(e) => setRegistrationForm({...registrationForm, username: e.target.value})}
                  disabled={isRegistering}
                  required
                />
                <input
                  type="text"
                  placeholder="Display Name (optional)"
                  value={registrationForm.displayName}
                  onChange={(e) => setRegistrationForm({...registrationForm, displayName: e.target.value})}
                  disabled={isRegistering}
                />
              </>
            )}
            
            <button type="submit" disabled={isRegistering} className="button-primary">
              {isRegistering ? '🔄 Creating Passkey...' : `🔐 Create ${authMode === 'entra-id' ? 'Enterprise ' : ''}Passkey`}
            </button>
            
            <button 
              type="button" 
              onClick={() => {
                setShowRegistration(false);
                if (authMode === 'entra-id') {
                  setAuthState('entra-authenticated');
                }
              }}
              className="button-secondary"
              disabled={isRegistering}
            >
              Cancel
            </button>
          </form>

          <div className="registration-info">
            <h4>ℹ️ About Passkeys</h4>
            <ul>
              <li><strong>Passwordless:</strong> No passwords to remember or type</li>
              <li><strong>Secure:</strong> Uses cryptographic keys stored on your device</li>
              <li><strong>Convenient:</strong> Unlock with biometrics or device PIN</li>
              {authMode === 'entra-id' && (
                <li><strong>Enterprise:</strong> Linked to your organizational account</li>
              )}
            </ul>
          </div>
        </div>
      )}

      <div className="users-section">
        <h3>👥 Registered Users ({users.length})</h3>
        {users.length === 0 ? (
          <p>No users registered yet. Register a passkey to get started!</p>
        ) : (
          <div className="users-grid">
            {users.map(u => (
              <div key={u.id} className="user-card">
                <strong>{u.displayName || u.username}</strong>
                <small>{u.username}</small>
                <span className="passkey-count">{u.authenticatorCount} passkey{u.authenticatorCount !== 1 ? 's' : ''}</span>
                {u.username.includes('@MngEnvMCAP490549.onmicrosoft.com') && (
                  <span className="enterprise-badge">🏢 Enterprise</span>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export default App;