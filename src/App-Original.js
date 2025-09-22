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
  const [error, setError] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isRegistering, setIsRegistering] = useState(false);
  const [showRegistration, setShowRegistration] = useState(false);
  const [registrationForm, setRegistrationForm] = useState({ username: '', displayName: '' });
  const [webAuthnSupport, setWebAuthnSupport] = useState({ supported: false, platformAvailable: false });
  const [users, setUsers] = useState([]);

  useEffect(() => {
    const init = async () => {
      try {
        const supported = browserSupportsWebAuthn();
        let platformAvailable = false;
        
        try {
          platformAvailable = await platformAuthenticatorIsAvailable();
        } catch (e) {
          console.warn('Platform auth check failed:', e);
        }
        
        setWebAuthnSupport({ supported, platformAvailable });
        
        if (!supported) {
          setError('WebAuthn not supported');
          setAuthState('error');
          return;
        }
        
        // Check session
        try {
          const response = await api.get('/api/auth/session');
          if (response.data?.user) {
            setUser(response.data.user);
            setAuthState('authenticated');
          } else {
            setAuthState('unauthenticated');
          }
        } catch (err) {
          setAuthState('unauthenticated');
        }
        
        // Load users
        try {
          const usersResponse = await api.get('/api/users');
          setUsers(usersResponse.data);
        } catch (err) {
          console.warn('Failed to load users:', err);
        }
        
      } catch (err) {
        setError('Initialization failed');
        setAuthState('error');
      }
    };
    
    init();
  }, []);

  const handleAuth = async () => {
    setIsLoading(true);
    setError(null);
    
    try {
      const optionsResponse = await api.post('/api/webauthn/generate-authentication-options', {});
      const authResponse = await startAuthentication(optionsResponse.data);
      const verifyResponse = await api.post('/api/webauthn/verify-authentication', authResponse);
      
      if (verifyResponse.data.verified) {
        setUser(verifyResponse.data.user);
        setAuthState('authenticated');
      }
    } catch (err) {
      setError(err.message || 'Authentication failed');
    } finally {
      setIsLoading(false);
    }
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    
    if (!registrationForm.username.trim()) {
      setError('Username is required');
      return;
    }

    setIsRegistering(true);
    setError(null);

    try {
      // Generate registration options
      const optionsResponse = await api.post('/api/webauthn/generate-registration-options', {
        username: registrationForm.username.trim(),
        displayName: registrationForm.displayName.trim() || registrationForm.username.trim()
      });

      // Start registration with the browser WebAuthn API
      const registrationResponse = await startRegistration(optionsResponse.data);

      // Verify registration with server
      const verifyResponse = await api.post('/api/webauthn/verify-registration', registrationResponse);

      if (verifyResponse.data.verified) {
        setShowRegistration(false);
        setRegistrationForm({ username: '', displayName: '' });
        
        // Refresh users list
        try {
          const usersResponse = await api.get('/api/users');
          setUsers(usersResponse.data);
        } catch (err) {
          console.warn('Failed to refresh users:', err);
        }
        
        // Show success message
        alert('Passkey registered successfully! You can now sign in.');
      }
    } catch (err) {
      console.error('Registration error:', err);
      setError(err.message || 'Registration failed');
    } finally {
      setIsRegistering(false);
    }
  };

  const handleLogout = async () => {
    try {
      await api.post('/api/auth/logout');
    } catch (err) {
      console.warn('Logout error:', err);
    } finally {
      setAuthState('unauthenticated');
      setUser(null);
    }
  };

  if (authState === 'loading') {
    return (
      <div className="app">
        <h1>Loading...</h1>
        <p>Checking WebAuthn support and session</p>
      </div>
    );
  }

  if (authState === 'error') {
    return (
      <div className="app">
        <h1>Error</h1>
        <p>{error}</p>
        <button onClick={() => window.location.reload()}>Reload</button>
      </div>
    );
  }

  if (authState === 'unauthenticated') {
    return (
      <div className="app">
        <h1>🔐 Secure Kiosk</h1>
        <p>WebAuthn Support: {webAuthnSupport.supported ? 'Yes' : 'No'}</p>
        <p>Platform Auth: {webAuthnSupport.platformAvailable ? 'Yes' : 'No'}</p>
        
        {!showRegistration ? (
          <div>
            <h2>Authentication</h2>
            <div style={{ marginBottom: '20px' }}>
              <button 
                onClick={handleAuth}
                disabled={isLoading || !webAuthnSupport.supported}
                style={{ 
                  backgroundColor: '#007ACC', 
                  color: 'white', 
                  padding: '12px 24px', 
                  border: 'none', 
                  borderRadius: '6px', 
                  fontSize: '16px',
                  cursor: 'pointer',
                  marginRight: '10px'
                }}
              >
                {isLoading ? 'Authenticating...' : '🔐 Sign In with Passkey'}
              </button>
              
              <button
                onClick={() => setShowRegistration(true)}
                disabled={!webAuthnSupport.supported}
                style={{ 
                  backgroundColor: '#28A745', 
                  color: 'white', 
                  padding: '12px 24px', 
                  border: 'none', 
                  borderRadius: '6px', 
                  fontSize: '16px',
                  cursor: 'pointer'
                }}
              >
                📝 Register New Passkey
              </button>
            </div>
            
            {users.length > 0 && (
              <div style={{ marginTop: '30px' }}>
                <h3>Registered Users ({users.length})</h3>
                <div style={{ backgroundColor: '#f5f5f5', padding: '15px', borderRadius: '6px' }}>
                  {users.map(u => (
                    <div key={u.id} style={{ padding: '5px 0', borderBottom: '1px solid #ddd' }}>
                      <strong>{u.displayName || u.username}</strong> - {u.authenticatorCount} passkey(s)
                      <small style={{ color: '#666', marginLeft: '10px' }}>
                        (Created: {new Date(u.createdAt).toLocaleDateString()})
                      </small>
                    </div>
                  ))}
                </div>
              </div>
            )}
            
            {error && <p style={{color: 'red', backgroundColor: '#ffebee', padding: '10px', borderRadius: '4px'}}>{error}</p>}
          </div>
        ) : (
          <div>
            <h2>Register New Passkey</h2>
            <form onSubmit={handleRegister} style={{ maxWidth: '400px' }}>
              <div style={{ marginBottom: '15px' }}>
                <label style={{ display: 'block', marginBottom: '5px', fontWeight: 'bold' }}>
                  Username *
                </label>
                <input
                  type="text"
                  value={registrationForm.username}
                  onChange={(e) => setRegistrationForm({ ...registrationForm, username: e.target.value })}
                  placeholder="Enter your username"
                  required
                  disabled={isRegistering}
                  style={{ 
                    width: '100%', 
                    padding: '10px', 
                    border: '2px solid #ddd', 
                    borderRadius: '4px', 
                    fontSize: '16px'
                  }}
                />
              </div>
              
              <div style={{ marginBottom: '20px' }}>
                <label style={{ display: 'block', marginBottom: '5px', fontWeight: 'bold' }}>
                  Display Name (optional)
                </label>
                <input
                  type="text"
                  value={registrationForm.displayName}
                  onChange={(e) => setRegistrationForm({ ...registrationForm, displayName: e.target.value })}
                  placeholder="Enter your display name"
                  disabled={isRegistering}
                  style={{ 
                    width: '100%', 
                    padding: '10px', 
                    border: '2px solid #ddd', 
                    borderRadius: '4px', 
                    fontSize: '16px'
                  }}
                />
              </div>
              
              <div style={{ marginBottom: '15px' }}>
                <button 
                  type="submit"
                  disabled={isRegistering || !webAuthnSupport.supported}
                  style={{ 
                    backgroundColor: '#28A745', 
                    color: 'white', 
                    padding: '12px 24px', 
                    border: 'none', 
                    borderRadius: '6px', 
                    fontSize: '16px',
                    cursor: 'pointer',
                    marginRight: '10px'
                  }}
                >
                  {isRegistering ? 'Registering...' : '✅ Create Passkey'}
                </button>
                
                <button 
                  type="button"
                  onClick={() => {
                    setShowRegistration(false);
                    setRegistrationForm({ username: '', displayName: '' });
                    setError(null);
                  }}
                  disabled={isRegistering}
                  style={{ 
                    backgroundColor: '#6C757D', 
                    color: 'white', 
                    padding: '12px 24px', 
                    border: 'none', 
                    borderRadius: '6px', 
                    fontSize: '16px',
                    cursor: 'pointer'
                  }}
                >
                  Cancel
                </button>
              </div>
            </form>
            
            {error && <p style={{color: 'red', backgroundColor: '#ffebee', padding: '10px', borderRadius: '4px'}}>{error}</p>}
            
            <div style={{ marginTop: '20px', padding: '15px', backgroundColor: '#e7f3ff', borderRadius: '6px' }}>
              <h4>💡 How it works:</h4>
              <ol>
                <li>Enter your username and optional display name</li>
                <li>Click "Create Passkey" to start registration</li>
                <li>Your device will prompt you to use biometric authentication (fingerprint, face, etc.)</li>
                <li>Once registered, you can sign in using just your passkey</li>
              </ol>
            </div>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="app">
      <h1>🎉 Welcome {user?.displayName || user?.username}</h1>
      <p>You are authenticated!</p>
      <button onClick={handleLogout}>Logout</button>
      
      <div>
        <h2>User Info</h2>
        <pre>{JSON.stringify(user, null, 2)}</pre>
      </div>
    </div>
  );
}

export default App;