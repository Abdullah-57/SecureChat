// client/src/components/Auth.jsx
import { useState } from 'react';
import axios from 'axios';
import localforage from 'localforage';
import { generateIdentityKeys, exportKey } from '../utils/cryptoUtils';

const API_URL = "http://localhost:3001";

function Auth({ onLogin }) {
  const [isRegistering, setIsRegistering] = useState(false);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [twoFactorCode, setTwoFactorCode] = useState(""); 
  const [generated2FA, setGenerated2FA] = useState(null); 
  const [status, setStatus] = useState("");

  const handleRegister = async (e) => {
    e.preventDefault();
    setStatus("Now Generating Cryptographic Keys...");

    try {
      const { ecdhPair, rsaPair } = await generateIdentityKeys();
      await localforage.setItem(`priv_ecdh_${username}`, ecdhPair.privateKey);
      await localforage.setItem(`priv_rsa_${username}`, rsaPair.privateKey);

      const pubECDH = await exportKey(ecdhPair.publicKey);
      const pubRSA = await exportKey(rsaPair.publicKey);

      const res = await axios.post(`${API_URL}/register`, {
        username,
        password,
        publicKeyECDH: pubECDH,
        publicKeyRSA: pubRSA
      });

      // Show the 2FA Code to User
      setGenerated2FA(res.data.twoFactorSecret);
      setStatus("Registration Successful! SAVE YOUR CODE BELOW.");
      
    } catch (error) {
      console.error(error);
      setStatus("Error:There is Username taken or server issue.");
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    setStatus("Authenticating...");

    try {
      const res = await axios.post(`${API_URL}/login`, { 
          username, 
          password, 
          twoFactorCode
      });
      
      const privKey = await localforage.getItem(`priv_ecdh_${username}`);
      if (!privKey) {
        setStatus("Warning: No Private Keys found on this device.");
        return;
      }

      onLogin(res.data);
    } catch (error) {
      // Handle 2FA failure specifically
      if(error.response && error.response.status === 403) {
          setStatus("❌ INVALID 2FA CODE");
      } else {
          setStatus("Invalid Credentials");
      }
    }
  };

  return (
    <div style={{ 
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      background: 'linear-gradient(135deg, #0f172a 0%, #1e293b 100%)',
      padding: '20px'
    }}>
      <div style={{ 
        maxWidth: '480px', 
        width: '100%',
        padding: '40px', 
        borderRadius: '16px', 
        color: 'white', 
        background: 'linear-gradient(135deg, #1e293b 0%, #334155 100%)',
        boxShadow: '0 20px 60px rgba(0, 0, 0, 0.5)',
        border: '1px solid rgba(148, 163, 184, 0.2)'
      }}>
        {/* Header */}
        <div style={{ textAlign: 'center', marginBottom: '32px' }}>
          <div style={{ 
            fontSize: '3em', 
            marginBottom: '16px',
            background: 'linear-gradient(135deg, #3b82f6 0%, #2563eb 100%)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
            fontWeight: 'bold'
          }}>
            🔐
          </div>
          <h2 style={{ 
            margin: '0 0 8px 0', 
            fontSize: '1.8em', 
            fontWeight: '600',
            color: '#f1f5f9'
          }}>
            {isRegistering ? "Secure Registration" : "2FA Login"}
          </h2>
          <p style={{ 
            margin: 0, 
            color: '#94a3b8', 
            fontSize: '0.95em' 
          }}>
            {isRegistering ? "Create your encrypted account" : "Welcome back! Enter your credentials"}
          </p>
        </div>
        
        {/* SUCCESSFUL REGISTRATION SCREEN */}
        {generated2FA ? (
          <div style={{ 
            background: 'linear-gradient(135deg, #10b981 0%, #059669 100%)', 
            padding: '32px', 
            borderRadius: '12px', 
            textAlign: 'center',
            boxShadow: '0 8px 24px rgba(16, 185, 129, 0.3)',
            border: '1px solid rgba(16, 185, 129, 0.3)'
          }}>
            <div style={{ fontSize: '3em', marginBottom: '16px' }}>✅</div>
            <h3 style={{ 
              color: 'white', 
              margin: '0 0 12px 0', 
              fontSize: '1.5em',
              fontWeight: '600'
            }}>
              Registration Complete!
            </h3>
            <p style={{ 
              color: 'rgba(255, 255, 255, 0.9)', 
              marginBottom: '20px',
              fontSize: '1em'
            }}>
              Your Security Code is:
            </p>
            <div style={{ 
              background: 'rgba(255, 255, 255, 0.2)', 
              padding: '20px', 
              borderRadius: '10px',
              marginBottom: '16px',
              border: '2px dashed rgba(255, 255, 255, 0.4)',
              backdropFilter: 'blur(10px)'
            }}>
              <h1 style={{ 
                letterSpacing: '8px', 
                fontSize: '2.2em',
                margin: 0,
                fontWeight: '700',
                color: 'white',
                fontFamily: 'monospace'
              }}>
                {generated2FA}
              </h1>
            </div>
            <div style={{ 
              background: 'rgba(239, 68, 68, 0.2)', 
              padding: '12px', 
              borderRadius: '8px',
              marginBottom: '20px',
              border: '1px solid rgba(239, 68, 68, 0.4)'
            }}>
              <p style={{ 
                color: '#fecaca', 
                fontSize: '0.9em',
                margin: 0,
                fontWeight: '600'
              }}>
                ⚠️ Write this down! You need it to login.
              </p>
            </div>
            <button 
              onClick={() => { setIsRegistering(false); setGenerated2FA(null); }} 
              style={{ 
                padding: '14px 28px', 
                marginTop: '8px',
                background: 'rgba(255, 255, 255, 0.2)',
                color: 'white',
                border: '1px solid rgba(255, 255, 255, 0.3)',
                borderRadius: '8px',
                fontSize: '1em',
                fontWeight: '600',
                cursor: 'pointer',
                transition: 'all 0.3s ease',
                width: '100%',
                backdropFilter: 'blur(10px)'
              }}
              onMouseOver={(e) => {
                e.target.style.background = 'rgba(255, 255, 255, 0.3)';
                e.target.style.transform = 'translateY(-2px)';
              }}
              onMouseOut={(e) => {
                e.target.style.background = 'rgba(255, 255, 255, 0.2)';
                e.target.style.transform = 'translateY(0)';
              }}
            >
              Go to Login →
            </button>
          </div>
        ) : (
          <form onSubmit={isRegistering ? handleRegister : handleLogin}>
            <div style={{ marginBottom: '20px' }}>
              <label style={{ 
                display: 'block', 
                marginBottom: '8px', 
                color: '#e2e8f0',
                fontSize: '0.9em',
                fontWeight: '500'
              }}>
                Username
              </label>
              <input 
                type="text" 
                placeholder="Enter your username" 
                value={username} 
                onChange={e => setUsername(e.target.value)} 
                style={{ 
                  width: '100%', 
                  padding: '12px 16px',
                  borderRadius: '8px',
                  border: '1px solid rgba(148, 163, 184, 0.3)',
                  background: 'rgba(15, 23, 42, 0.6)',
                  color: 'white',
                  fontSize: '1em',
                  outline: 'none',
                  transition: 'all 0.3s ease',
                  boxSizing: 'border-box'
                }}
                onFocus={(e) => e.target.style.borderColor = '#3b82f6'}
                onBlur={(e) => e.target.style.borderColor = 'rgba(148, 163, 184, 0.3)'}
                required 
              />
            </div>
            
            <div style={{ marginBottom: '20px' }}>
              <label style={{ 
                display: 'block', 
                marginBottom: '8px', 
                color: '#e2e8f0',
                fontSize: '0.9em',
                fontWeight: '500'
              }}>
                Password
              </label>
              <input 
                type="password" 
                placeholder="Enter your password" 
                value={password} 
                onChange={e => setPassword(e.target.value)} 
                style={{ 
                  width: '100%', 
                  padding: '12px 16px',
                  borderRadius: '8px',
                  border: '1px solid rgba(148, 163, 184, 0.3)',
                  background: 'rgba(15, 23, 42, 0.6)',
                  color: 'white',
                  fontSize: '1em',
                  outline: 'none',
                  transition: 'all 0.3s ease',
                  boxSizing: 'border-box'
                }}
                onFocus={(e) => e.target.style.borderColor = '#3b82f6'}
                onBlur={(e) => e.target.style.borderColor = 'rgba(148, 163, 184, 0.3)'}
                required 
              />
            </div>
            
            {/* 2FA INPUT FOR LOGIN */}
            {!isRegistering && (
              <div style={{ marginBottom: '24px' }}>
                <label style={{ 
                  display: 'block', 
                  marginBottom: '8px', 
                  color: '#e2e8f0',
                  fontSize: '0.9em',
                  fontWeight: '500'
                }}>
                  🔐 Security Code
                </label>
                <input 
                  type="text" 
                  placeholder="Enter 6-digit code" 
                  value={twoFactorCode} 
                  onChange={e => setTwoFactorCode(e.target.value)} 
                  style={{ 
                    width: '100%', 
                    padding: '12px 16px',
                    borderRadius: '8px',
                    border: '2px solid rgba(59, 130, 246, 0.5)',
                    background: 'rgba(15, 23, 42, 0.6)',
                    color: 'white',
                    fontSize: '1.1em',
                    outline: 'none',
                    transition: 'all 0.3s ease',
                    letterSpacing: '4px',
                    textAlign: 'center',
                    fontFamily: 'monospace',
                    fontWeight: '600',
                    boxSizing: 'border-box'
                  }}
                  onFocus={(e) => {
                    e.target.style.borderColor = '#3b82f6';
                    e.target.style.boxShadow = '0 0 0 3px rgba(59, 130, 246, 0.2)';
                  }}
                  onBlur={(e) => {
                    e.target.style.borderColor = 'rgba(59, 130, 246, 0.5)';
                    e.target.style.boxShadow = 'none';
                  }}
                  required 
                />
              </div>
            )}

            <button 
              type="submit" 
              style={{ 
                width: '100%', 
                padding: '14px',
                background: 'linear-gradient(135deg, #3b82f6 0%, #2563eb 100%)',
                color: 'white',
                border: 'none',
                borderRadius: '8px',
                fontSize: '1.05em',
                fontWeight: '600',
                cursor: 'pointer',
                transition: 'all 0.3s ease',
                boxShadow: '0 4px 12px rgba(59, 130, 246, 0.4)',
                marginBottom: '16px'
              }}
              onMouseOver={(e) => {
                e.target.style.transform = 'translateY(-2px)';
                e.target.style.boxShadow = '0 6px 20px rgba(59, 130, 246, 0.5)';
              }}
              onMouseOut={(e) => {
                e.target.style.transform = 'translateY(0)';
                e.target.style.boxShadow = '0 4px 12px rgba(59, 130, 246, 0.4)';
              }}
            >
              {isRegistering ? "🔑 Generate Keys & Register" : "🚀 Login with 2FA"}
            </button>
          </form>
        )}

        {!generated2FA && (
          <div style={{ 
            textAlign: 'center', 
            marginTop: '24px',
            paddingTop: '24px',
            borderTop: '1px solid rgba(148, 163, 184, 0.2)'
          }}>
            <p style={{ 
              margin: 0,
              fontSize: '0.95em', 
              cursor: 'pointer', 
              color: '#94a3b8',
              transition: 'color 0.3s ease'
            }} 
            onClick={() => setIsRegistering(!isRegistering)}
            onMouseOver={(e) => e.target.style.color = '#3b82f6'}
            onMouseOut={(e) => e.target.style.color = '#94a3b8'}
            >
              {isRegistering ? "Already have an account? Login →" : "Need an account? Register →"}
            </p>
          </div>
        )}

        {status && (
          <div style={{ 
            marginTop: '20px',
            padding: '14px 18px',
            borderRadius: '8px',
            background: status.includes("Success") || status.includes("✓")
              ? 'rgba(16, 185, 129, 0.2)'
              : 'rgba(239, 68, 68, 0.2)',
            border: `1px solid ${status.includes("Success") || status.includes("✓") ? 'rgba(16, 185, 129, 0.4)' : 'rgba(239, 68, 68, 0.4)'}`,
            color: status.includes("Success") || status.includes("✓") ? '#6ee7b7' : '#fca5a5',
            textAlign: 'center',
            fontSize: '0.95em',
            fontWeight: '500'
          }}>
            {status}
          </div>
        )}
      </div>
    </div>
  );
}

export default Auth;