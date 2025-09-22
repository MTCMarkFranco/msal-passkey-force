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
        
        <div>
          <h2>Sign In</h2>
          <button 
            onClick={handleAuth}
            disabled={isLoading || !webAuthnSupport.supported}
          >
            {isLoading ? 'Authenticating...' : 'Sign In with Passkey'}
          </button>
          
          {users.length > 0 && (
            <div>
              <h3>Registered Users ({users.length})</h3>
              {users.map(u => (
                <div key={u.id}>
                  {u.displayName || u.username} - {u.authenticatorCount} passkey(s)
                </div>
              ))}
            </div>
          )}
          
          {error && <p style={{color: 'red'}}>{error}</p>}
        </div>
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