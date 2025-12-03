/**
 * Auth Component - Authentication & Registration UI
 * 
 * Handles:
 * - User registration with cryptographic key generation (ECDH + RSA)
 * - User login with password + 2FA authentication
 * - Private key storage in browser's IndexedDB (via localforage)
 * - Public key exchange with server for E2EE setup
 * 
 * Security Features:
 * - Private keys never leave the client device
 * - Public keys sent to server for key exchange
 * - 2FA code required for login (generated during registration)
 */

// ==================== Imports ====================
import { useState } from 'react';
import axios from 'axios';
import localforage from 'localforage'; // IndexedDB wrapper for storing private keys locally
import { generateIdentityKeys, exportKey } from '../utils/cryptoUtils';

// ==================== Constants ====================
const API_URL = "http://localhost:3001"; // Backend server URL

// ==================== Component ====================
function Auth({ onLogin }) {
  console.log('🔐 Auth component initialized');
  
  // ==================== State Management ====================
  const [isRegistering, setIsRegistering] = useState(false); // Toggle between login/register modes
  const [username, setUsername] = useState(""); // User's username input
  const [password, setPassword] = useState(""); // User's password input
  const [twoFactorCode, setTwoFactorCode] = useState(""); // 2FA code for login
  const [generated2FA, setGenerated2FA] = useState(null); // 2FA code received after registration
  const [status, setStatus] = useState(""); // Status message for user feedback

  /**
   * handleRegister - Registration Handler
   * 
   * Process:
   * 1. Generate ECDH and RSA key pairs (for E2EE)
   * 2. Store private keys locally in IndexedDB (never sent to server)
   * 3. Export public keys and send to server
   * 4. Receive 2FA secret code from server
   * 5. Display 2FA code to user (must be saved for future logins)
   */
  const handleRegister = async (e) => {
    e.preventDefault();
    console.log('📝 Registration process started');
    console.log(`   Username: ${username}`);
    setStatus("Generating Cryptographic Keys...");

    try {
      // Step 1: Generate cryptographic key pairs
      console.log('🔑 Generating ECDH and RSA key pairs...');
      const { ecdhPair, rsaPair } = await generateIdentityKeys();
      console.log('✅ Key pairs generated successfully');
      
      // Step 2: Store private keys locally (IndexedDB via localforage)
      // Private keys NEVER leave the client device - critical for E2EE security
      console.log(`💾 Storing private keys in IndexedDB for user: ${username}`);
      await localforage.setItem(`priv_ecdh_${username}`, ecdhPair.privateKey);
      await localforage.setItem(`priv_rsa_${username}`, rsaPair.privateKey);
      console.log('✅ Private keys stored locally');

      // Step 3: Export public keys (safe to send to server)
      console.log('📤 Exporting public keys...');
      const pubECDH = await exportKey(ecdhPair.publicKey);
      const pubRSA = await exportKey(rsaPair.publicKey);
      console.log(`   ECDH public key length: ${pubECDH.length} chars`);
      console.log(`   RSA public key length: ${pubRSA.length} chars`);

      // Step 4: Send registration data to server
      console.log(`📡 Sending registration request to ${API_URL}/register`);
      const res = await axios.post(`${API_URL}/register`, {
        username,
        password,
        publicKeyECDH: pubECDH,
        publicKeyRSA: pubRSA
      });
      console.log('✅ Registration request successful');

      // Step 5: Display 2FA code to user
      const twoFactorSecret = res.data.twoFactorSecret;
      console.log(`🔐 Received 2FA secret: ${twoFactorSecret}`);
      console.log('⚠️  User must save this code for future logins!');
      
      setGenerated2FA(twoFactorSecret);
      setStatus("Registration Successful! SAVE YOUR CODE BELOW.");
      
    } catch (error) {
      console.error('❌ Registration failed:', error);
      if (error.response) {
        console.error(`   Server response: ${error.response.status} - ${error.response.data?.error || 'Unknown error'}`);
      } else if (error.request) {
        console.error('   No response from server - check server connection');
      } else {
        console.error(`   Error: ${error.message}`);
      }
      setStatus("Error: Username taken or server issue.");
    }
  };

  /**
   * handleLogin - Login Handler
   * 
   * Process:
   * 1. Send credentials (username, password, 2FA code) to server
   * 2. Verify private keys exist locally (required for E2EE)
   * 3. On success, call onLogin callback with user data and public keys
   * 
   * Security:
   * - Password is sent to server (hashed server-side)
   * - 2FA code must match server's stored secret
   * - Private keys remain on client device only
   */
  const handleLogin = async (e) => {
    e.preventDefault();
    console.log('🔐 Login process started');
    console.log(`   Username: ${username}`);
    console.log(`   2FA Code provided: ${twoFactorCode ? 'Yes' : 'No'}`);
    setStatus("Authenticating...");

    try {
      // Step 1: Authenticate with server (password + 2FA)
      console.log(`📡 Sending login request to ${API_URL}/login`);
      const res = await axios.post(`${API_URL}/login`, { 
          username, 
          password, 
          twoFactorCode
      });
      console.log('✅ Login request successful');
      console.log(`   Received user data for: ${res.data.username}`);
      console.log(`   Has ECDH public key: ${!!res.data.publicKeyECDH}`);
      console.log(`   Has RSA public key: ${!!res.data.publicKeyRSA}`);
      
      // Step 2: Verify private keys exist locally
      // Private keys are required for decrypting messages (E2EE)
      console.log(`🔍 Checking for private keys in IndexedDB...`);
      const privKey = await localforage.getItem(`priv_ecdh_${username}`);
      if (!privKey) {
        console.error(`❌ Private keys not found for user: ${username}`);
        console.error('   User must register on this device or import keys');
        setStatus("Warning: Private Keys not found on this device.");
        return;
      }
      console.log('✅ Private keys found locally');

      // Step 3: Login successful - pass user data to parent component
      console.log(`✅ Login successful! Passing user data to parent component`);
      onLogin(res.data);
      
    } catch (error) {
      console.error('❌ Login failed:', error);
      
      // Handle different error types
      if(error.response) {
        const statusCode = error.response.status;
        console.error(`   Server response: ${statusCode}`);
        
        if(statusCode === 403) {
          // 2FA code mismatch
          console.error('   Reason: Invalid 2FA code');
          setStatus("❌ INVALID 2FA CODE");
        } else if(statusCode === 401) {
          // Invalid password
          console.error('   Reason: Invalid password');
          setStatus("Invalid Credentials");
        } else if(statusCode === 404) {
          // User not found
          console.error('   Reason: User not found');
          setStatus("Invalid Credentials");
        } else {
          console.error(`   Reason: ${error.response.data?.error || 'Unknown error'}`);
          setStatus("Invalid Credentials");
        }
      } else if(error.request) {
        console.error('   No response from server - check server connection');
        setStatus("Connection error. Please check server.");
      } else {
        console.error(`   Error: ${error.message}`);
        setStatus("Invalid Credentials");
      }
    }
  };

  // ==================== Render ====================
  return (
    // Main container - full viewport with gradient background
    <div style={{ 
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      background: 'linear-gradient(135deg, #0f172a 0%, #1e293b 100%)',
      padding: '20px'
    }}>
      {/* Auth card container */}
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
        {/* ==================== Header Section ==================== */}
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
        
        {/* ==================== Registration Success Screen ==================== */}
        {/* Displayed after successful registration - shows 2FA code */}
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
            {/* Button to return to login screen after viewing 2FA code */}
            <button 
              onClick={() => { 
                console.log('🔄 Switching to login mode');
                setIsRegistering(false); 
                setGenerated2FA(null); 
              }} 
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
          /* ==================== Login/Registration Form ==================== */
          <form onSubmit={isRegistering ? handleRegister : handleLogin}>
            {/* Username Input Field */}
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
            
            {/* Password Input Field */}
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
            
            {/* ==================== 2FA Code Input (Login Only) ==================== */}
            {/* Only shown during login - not needed for registration */}
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

            {/* Submit Button - Triggers handleRegister or handleLogin */}
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

        {/* ==================== Toggle Between Login/Register ==================== */}
        {/* Only shown when not displaying 2FA code */}
        {!generated2FA && (
          <div style={{ 
            textAlign: 'center', 
            marginTop: '24px',
            paddingTop: '24px',
            borderTop: '1px solid rgba(148, 163, 184, 0.2)'
          }}>
            {/* Clickable text to switch between login and registration modes */}
            <p style={{ 
              margin: 0,
              fontSize: '0.95em', 
              cursor: 'pointer', 
              color: '#94a3b8',
              transition: 'color 0.3s ease'
            }} 
            onClick={() => {
              const newMode = !isRegistering;
              console.log(`🔄 Switching to ${newMode ? 'registration' : 'login'} mode`);
              setIsRegistering(newMode);
            }}
            onMouseOver={(e) => e.target.style.color = '#3b82f6'}
            onMouseOut={(e) => e.target.style.color = '#94a3b8'}
            >
              {isRegistering ? "Already have an account? Login →" : "Need an account? Register →"}
            </p>
          </div>
        )}

        {/* ==================== Status Message Display ==================== */}
        {/* Shows success/error messages with color-coded styling */}
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