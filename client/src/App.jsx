import { useState } from 'react';
import Auth from './components/Auth';
import Chat from './components/Chat'; 

function App() {
  const [user, setUser] = useState(null);

  return (
    <div style={{ 
      padding: '0', 
      fontFamily: 'system-ui, -apple-system, sans-serif', 
      backgroundColor: '#0f172a', 
      minHeight: '100vh', 
      color: 'white' 
    }}>
      {!user ? (
        <Auth onLogin={(userData) => setUser(userData)} />
      ) : (
        <div style={{ 
          maxWidth: '1400px', 
          margin: '0 auto', 
          padding: '20px',
          height: '100vh',
          display: 'flex',
          flexDirection: 'column'
        }}>
          {/* Header */}
          <div style={{ 
            display: 'flex', 
            justifyContent: 'space-between', 
            alignItems: 'center', 
            marginBottom: '20px',
            padding: '20px',
            background: 'linear-gradient(135deg, #1e293b 0%, #334155 100%)',
            borderRadius: '12px',
            boxShadow: '0 4px 6px rgba(0, 0, 0, 0.3)'
          }}>
            <div>
              <h1 style={{ margin: '0 0 8px 0', fontSize: '2em', fontWeight: '600' }}>
                Welcome, {user.username}
              </h1>
              <div style={{ fontSize: '0.85em', color: '#94a3b8' }}>
                Secure E2E Encrypted Messaging
              </div>
            </div>
            <button 
              onClick={() => window.location.reload()} 
              style={{ 
                padding: '12px 24px', 
                background: 'linear-gradient(135deg, #ef4444 0%, #dc2626 100%)', 
                color: 'white', 
                border: 'none', 
                cursor: 'pointer',
                borderRadius: '8px',
                fontSize: '1em',
                fontWeight: '600',
                boxShadow: '0 4px 6px rgba(239, 68, 68, 0.3)',
                transition: 'all 0.3s ease'
              }}
              onMouseOver={(e) => e.target.style.transform = 'translateY(-2px)'}
              onMouseOut={(e) => e.target.style.transform = 'translateY(0)'}
            >
              Logout
            </button>
          </div>
          
          {/* Status Bar */}
          <div style={{ 
            background: 'linear-gradient(135deg, #059669 0%, #10b981 100%)', 
            padding: '16px 20px', 
            borderRadius: '12px', 
            marginBottom: '20px',
            boxShadow: '0 4px 6px rgba(16, 185, 129, 0.2)',
            display: 'flex',
            alignItems: 'center',
            gap: '12px'
          }}>
            <div style={{ 
              fontSize: '24px',
              background: 'rgba(255, 255, 255, 0.2)',
              borderRadius: '50%',
              width: '40px',
              height: '40px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center'
            }}>
              ✓
            </div>
            <div style={{ flex: 1 }}>
              <p style={{ margin: 0, color: 'white', fontWeight: '600', fontSize: '1.05em' }}>
                Authenticated & Secure Keys Loaded
              </p>
              <p style={{ margin: '4px 0 0 0', fontSize: '0.85em', color: 'rgba(255, 255, 255, 0.8)' }}>
                RSA Fingerprint: {user.publicKeyRSA.substring(0, 50)}...
              </p>
            </div>
          </div>

          {/* THE CHAT COMPONENT */}
          <div style={{ flex: 1, minHeight: 0 }}>
            <Chat user={user} />
          </div>
        </div>
      )}
    </div>
  );
}

export default App;