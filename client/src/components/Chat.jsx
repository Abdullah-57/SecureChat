import { useState, useEffect, useRef } from 'react';
import { io } from 'socket.io-client';
import axios from 'axios';
import localforage from 'localforage';
import { 
  generateIdentityKeys, exportKey, importKey, deriveSharedSecret, 
  deriveSessionKey, computeKeyHash, 
  encryptData, decryptData, signData, verifySignature,
  encryptFile, decryptFile 
} from '../utils/cryptoUtils';

const SOCKET_URL = "http://localhost:3001";
const API_URL = "http://localhost:3001";
const CHUNK_SIZE = 64 * 1024; // 64KB Chunks

const blobToBase64 = (blob) => {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onloadend = () => resolve(reader.result);
    reader.onerror = reject;
    reader.readAsDataURL(blob);
  });
};

function Chat({ user }) {
  // allUsers. Everyone in DB. onlineUsers: Just the connected ones.
  const [allUsers, setAllUsers] = useState([]);
  const [onlineUsers, setOnlineUsers] = useState([]);
  const [selectedUser, setSelectedUser] = useState(null);
  const [secureMode, setSecureMode] = useState(false);
  const [incomingOffer, setIncomingOffer] = useState(null);
  const [messages, setMessages] = useState([]);
  const [inputText, setInputText] = useState("");

  const socketRef = useRef();
  const sessionKeyRef = useRef(null);
  const remoteSequenceRef = useRef(0);
  const mySequenceRef = useRef(0);
  const selectedUserRef = useRef(null);
  
  // Buffer to hold incoming chunks before reassembly
  // Format: { fileId: { chunks: [], count: 0, total: 0, ... } }
  const fileReassemblyMap = useRef({});

  const myUsername = user.username;

  useEffect(() => { selectedUserRef.current = selectedUser; }, [selectedUser]);

  // Socket Setup
  useEffect(() => {
    // 1. Fetch All Users (The Phonebook)
    const fetchUsers = async () => {
      try {
        const res = await axios.get(`${API_URL}/users`);
        // Remove myself from list
        const others = res.data.filter(u => u.username !== myUsername);
        setAllUsers(others);
      } catch (e) { console.error("Failed to fetch contacts"); }
    };
    // 2. Initial Fetch
    fetchUsers();

    // 3. Connect Socket
    socketRef.current = io(SOCKET_URL);
    const socket = socketRef.current;
    window.testSocket = socket;

    socket.emit('join', myUsername);

    socket.on('online_users_update', (users) => {
      setOnlineUsers(users);
      fetchUsers();   // Update the Phonebook whenever someone connects/disconnects
    });

      socket.on('secure_signal', async (data) => {
        const { sender, type, payload } = data;
        if (type === 'OFFER') setIncomingOffer({ sender, payload });
        if (type === 'ANSWER') await handleAnswer(sender, payload);
      });

      socket.on('encrypted_message', async (data) => await handleIncomingMessage(data));

      return () => socket.disconnect();
    }, [myUsername]);
  
    // Load History
    useEffect(() => {
      if (!selectedUser) return;
      const loadSessionData = async () => {
        const historyKey = `chat_${myUsername}_${selectedUser}`;
        const savedMessages = await localforage.getItem(historyKey) || [];
        setMessages(savedMessages);

        const sessionKeyKey = `session_${myUsername}_${selectedUser}`;
        const savedKey = await localforage.getItem(sessionKeyKey);

        if (savedKey) {
          sessionKeyRef.current = savedKey;
          setSecureMode(true);
        } else {
          sessionKeyRef.current = null;
          setSecureMode(false);
        }
      };
      loadSessionData();
    }, [selectedUser, myUsername]);
    
    const isSelectedUserOnline = () => {
      return onlineUsers.includes(selectedUser);
    };

    const saveMsg = async (msgObj, targetUser) => {
      setMessages(prev => [...prev, msgObj]);
      const historyKey = `chat_${myUsername}_${targetUser}`;
      const currentHistory = await localforage.getItem(historyKey) || [];
      await localforage.setItem(historyKey, [...currentHistory, msgObj]);
    };

    const addSystemMessage = (text) => setMessages(prev => [...prev, { text, isSystem: true }]);

    const handleAnswer = async (sender, payload) => {
      try {
        const myHash = await computeKeyHash(sessionKeyRef.current);
        if (myHash !== payload.keyHash) {
          alert("CRITICAL SECURITY WARNING: Key Confirmation Failed! MITM Detected.");
          reportSecurityEvent("KEY_CONFIRMATION_FAIL", { sender });
          return;
        }
        setSecureMode(true);
        remoteSequenceRef.current = 0;
        mySequenceRef.current = 0;
        await localforage.setItem(`session_${myUsername}_${sender}`, sessionKeyRef.current);
        addSystemMessage(`✅ Key Confirmed. Secure Channel Established with ${sender}.`);
      } catch (e) { console.error(e); }
    };

    const acceptChat = async () => {
      if (!incomingOffer) return;
      const { sender, payload } = incomingOffer;
      try {
        const { data: senderMeta } = await axios.get(`${API_URL}/user/${sender}`);
        const senderIdentityPub = await importKey(senderMeta.publicKeyRSA, "RSA");

        // Check Timestamp freshness (e.g., 2 mins)
        if (Date.now() - payload.timestamp > 120000) {
          alert("❌ SECURITY ALERT: Stale Handshake Offer (Replay Attack?)");
          return;
        }

        // Verify Signature over (Key + Timestamp)
        const payloadToVerify = `${payload.ephemeralPub}|||${payload.timestamp}`;
      
        // MITM Defense Check
        const isValid = await verifySignature(payloadToVerify, payload.signature, senderIdentityPub);
        if (!isValid) {
          console.group("%c🚨 SECURITY ALERT: MITM ATTACK BLOCKED", "color: red; font-size: 14px; font-weight: bold;");
          console.error("❌ HANDSHAKE REJECTED: Signature Verification Failed");
          console.log("1. Attacker Identity:", sender);
          console.log("2. Received Public Key:", payload.ephemeralPub.substring(0, 30) + "...");
          console.log("3. Analysis: The signature does NOT match the public key stored in the directory.");
          console.log("4. Conclusion: Someone is impersonating", sender);
          console.groupEnd();
          alert("❌ SECURITY ALERT: Signature Mismatch! MITM Attack Blocked.");
          reportSecurityEvent("MITM_SIGNATURE_MISMATCH", {
            attacker: sender,
            desc: "Invalid RSA Signature on Handshake"
          });
          return;
        }

        // console.log("⚠️ MITM DEMO: Ignoring invalid signature to show vulnerability.");

        const myStaticPriv = await localforage.getItem(`priv_ecdh_${myUsername}`);
        const aliceEphemeralPub = await importKey(payload.ephemeralPub, "ECDH");
        const sharedBits = await deriveSharedSecret(myStaticPriv, aliceEphemeralPub);
      
        const sessionKey = await deriveSessionKey(sharedBits);
        sessionKeyRef.current = sessionKey;
        await localforage.setItem(`session_${myUsername}_${sender}`, sessionKey);

        const keyHash = await computeKeyHash(sessionKey);

        socketRef.current.emit('secure_signal', {
          targetUser: sender, type: 'ANSWER', payload: { keyHash }
        });

        setSelectedUser(sender);
        setSecureMode(true);
        setIncomingOffer(null);
        remoteSequenceRef.current = 0;
        mySequenceRef.current = 0;
        addSystemMessage(`✅ Key Confirmed. Secure Channel Established with ${sender}`);
      } catch (err) { console.error(err); }
    };

    const startChat = async (targetUser) => {
      setSelectedUser(targetUser);
      const savedKey = await localforage.getItem(`session_${myUsername}_${targetUser}`);
      if (savedKey) {
        sessionKeyRef.current = savedKey;
        setSecureMode(true);
        return;
      }
      // Check if online before handshake
      if (!onlineUsers.includes(targetUser)) {
        setSecureMode(false);
        setMessages([]); // Load history only (done by effect)
        return;
      }
      setSecureMode(false);
      setMessages([]);
      try {
        const { data: targetMeta } = await axios.get(`${API_URL}/user/${targetUser}`);
        const { ecdhPair } = await generateIdentityKeys();
        const targetStaticECDH = await importKey(targetMeta.publicKeyECDH, "ECDH");
        const sharedBits = await deriveSharedSecret(ecdhPair.privateKey, targetStaticECDH);
        const sessionKey = await deriveSessionKey(sharedBits);
        sessionKeyRef.current = sessionKey;

        const myIdentityPriv = await localforage.getItem(`priv_rsa_${myUsername}`);
        const myEphemeralPub = await exportKey(ecdhPair.publicKey);

        // Add Timestamp to signature payload
        const timestamp = Date.now();
        const payloadToSign = `${myEphemeralPub}|||${timestamp}`;
        const signature = await signData(payloadToSign, myIdentityPriv);

        socketRef.current.emit('secure_signal', { targetUser, type: 'OFFER', payload: { ephemeralPub: myEphemeralPub, signature, timestamp } });
        addSystemMessage(`Handshake offer sent to ${targetUser}...`);
      } catch (err) { console.error(err); }
    };

    const sendMessage = async () => {
      if (!inputText.trim() || !secureMode) return;
      try {
        mySequenceRef.current += 1;
      
        // Add timestamp to signature payload
        const timestamp = Date.now();
        const payload = `${mySequenceRef.current}|||${timestamp}|||${inputText}`;
      
        const { ciphertext, iv } = await encryptData(payload, sessionKeyRef.current);

        console.log("CAPTURED PACKET:", { targetUser: selectedUser, ciphertext, iv });

        socketRef.current.emit('encrypted_message', { targetUser: selectedUser, ciphertext, iv });
        await saveMsg({ sender: "Me", text: inputText, isSelf: true }, selectedUser);
        setInputText("");
      } catch (err) { console.error(err); }
    };

    const reportSecurityEvent = async (type, details) => {
      try {
        await axios.post(`${API_URL}/report-security`, {
          eventType: type,
          details: { ...details, reporter: myUsername }
        });
      } catch (e) { console.error("Failed to report security event", e); }
    };

    const handleIncomingMessage = async (data) => {
      const { sender, ciphertext, iv, isFile, fileName, fileType, fileId, chunkIndex, totalChunks } = data;
      try {
        if (!sessionKeyRef.current) throw new Error("No Key");
        const activeUser = selectedUserRef.current;

        if (isFile) {
          // 1. Log Decryption Event (Proof for Rubric)
          console.log(`📥 Decrypting Chunk ${chunkIndex + 1}/${totalChunks} from ${sender}...`);
         
          // 2. Decrypt the Chunk
          const decryptedBuffer = await decryptFile({ ciphertext, iv }, sessionKeyRef.current);
          
          // 3. Initialize Buffer if new file
          if (!fileReassemblyMap.current[fileId]) {
            fileReassemblyMap.current[fileId] = {
              chunks: new Array(totalChunks),
              receivedCount: 0
            };
          }
          
          // 4. Store Chunk
          const fileEntry = fileReassemblyMap.current[fileId];
          fileEntry.chunks[chunkIndex] = decryptedBuffer;
          fileEntry.receivedCount++;
          
          // 5. Check Completion
          if (fileEntry.receivedCount === totalChunks) {
            console.log(`✅ File Reassembly Complete: ${fileName}`);
            
            // Combine Chunks into one Blob
            const finalBlob = new Blob(fileEntry.chunks, { type: fileType });
            const base64Data = await blobToBase64(finalBlob);
            
            const msgObj = {
              sender, isSelf: false, isFile: true,
              fileData: base64Data, fileName, fileType
            };

            // Cleanup RAM
            delete fileReassemblyMap.current[fileId];
               
            // Log to Server Audit
            reportSecurityEvent("FILE_RECEIVED", { sender, fileName, chunks: totalChunks });
           
            if (activeUser === sender) await saveMsg(msgObj, sender);
            else {
              const historyKey = `chat_${myUsername}_${sender}`;
              const currentHistory = await localforage.getItem(historyKey) || [];
              await localforage.setItem(historyKey, [...currentHistory, msgObj]);
            }
          }
        } else {
          const decryptedRaw = await decryptData({ ciphertext, iv }, sessionKeyRef.current);
          const [seqStr, timeStr, content] = decryptedRaw.split('|||');
          const seqNum = parseInt(seqStr, 10);
          const timestamp = parseInt(timeStr, 10);
           
          if (isNaN(seqNum) || isNaN(timestamp)) return;

          // Replay Attack
          if (seqNum <= remoteSequenceRef.current) {
            console.error(`REPLAY ATTACK: Seq ${seqNum}`);
            console.group("%c🛡️ REPLAY ATTACK DETECTED", "color: red; font-size: 14px; font-weight: bold;");
            console.error("❌ PACKET DROPPED: Duplicate or Old Sequence Number");
            console.table({
                "Received Sequence": seqNum,
                "Expected Sequence": `> ${remoteSequenceRef.current}`,
                "Timestamp": new Date(timestamp).toLocaleTimeString(),
                "Content": content,
                "Verdict": "MALICIOUS REPLAY"
            });
            console.groupEnd();
            addSystemMessage(`⛔ Security Alert: Replay Attack Detected. Ignored.`);
            reportSecurityEvent("REPLAY_ATTACK", {
              sender, seqNum, expected: remoteSequenceRef.current
            });
              
            return;
          }

          // Check Expired Message (e.g. > 2 mins old)
          if (Date.now() - timestamp > 120000) { // 2 minutes
            console.error("EXPIRED MESSAGE");
            addSystemMessage(`⚠️ Security Alert: Message Expired. Ignored.`);
            return;
          }

          remoteSequenceRef.current = seqNum;
           
          const msgObj = { sender, text: content, isSelf: false };
          if (activeUser === sender) await saveMsg(msgObj, sender);
          else {
            const historyKey = `chat_${myUsername}_${sender}`;
            const currentHistory = await localforage.getItem(historyKey) || [];
            await localforage.setItem(historyKey, [...currentHistory, msgObj]);
          }
        }
      } catch (err) {
        console.error("Decryption Failed", err);
        addSystemMessage(`⚠️ Decryption Error or Attack Attempt.`);
        reportSecurityEvent("DECRYPTION_FAIL", { sender, error: err.message });
      }
    };

    const handleFileSelect = async (e) => {
      const file = e.target.files[0];
      if (!file || !secureMode) return;

      // 1. Prepare Chunking Data
      const fileId = crypto.randomUUID();
      const totalChunks = Math.ceil(file.size / CHUNK_SIZE);

      console.log(`📤 Starting Upload: ${file.name} (${totalChunks} chunks)`);

      try {
        // 2. Loop through chunks
        for (let i = 0; i < totalChunks; i++) {
          const start = i * CHUNK_SIZE;
          const end = Math.min(file.size, start + CHUNK_SIZE);
          const chunk = file.slice(start, end);
          const arrayBuffer = await chunk.arrayBuffer();
        
          // 3. Log Encryption (Proof for Rubric)
          console.log(`🔒 Encrypting Chunk ${i + 1}/${totalChunks}...`);
        
          // 4. Encrypt Chunk
          const { ciphertext, iv } = await encryptFile(arrayBuffer, sessionKeyRef.current);
        
          // 5. Send Chunk
          socketRef.current.emit('encrypted_message', {
            targetUser: selectedUser,
            ciphertext,
            iv,
            isFile: true,
            fileName: file.name,
            fileType: file.type,
            fileId,       
            chunkIndex: i, 
            totalChunks
          });
        }

        // Display locally immediately
        const base64Data = await blobToBase64(file);
        await saveMsg({
          sender: "Me", isSelf: true, isFile: true,
          fileData: base64Data, fileName: file.name, fileType: file.type
        }, selectedUser);

      } catch (err) { console.error(err); }
    };

    // Demo Attack Tools
    const launchReplayAttack = async () => {
      if (messages.length === 0) return alert("Send a message first!");
      const lastMsg = messages[messages.length - 1];
      if (!lastMsg.text) return alert("Send text first");
      
      // Encrypt with OLD Sequence Number
      mySequenceRef.current -= 1;
      const timestamp = Date.now();
      const payload = `${mySequenceRef.current}|||${timestamp}|||${lastMsg.text}`;
      const { ciphertext, iv } = await encryptData(payload, sessionKeyRef.current);
      mySequenceRef.current += 1; // Restore

      console.log(`☠️ LAUNCHING REPLAY ATTACK`);
      socketRef.current.emit('encrypted_message', { targetUser: selectedUser, ciphertext, iv });
    };

    const launchMITMAttack = async () => {
      if (!selectedUser) return alert("Select a user first");
      
      console.log(`☠️ LAUNCHING MITM ATTACK`);
      
      // 1. Generate a NEW Key Pair (Mallory's Keys)
      const { ecdhPair } = await generateIdentityKeys();
      const malloryPub = await exportKey(ecdhPair.publicKey);
      
      // 2. Create a FAKE Signature (random bytes)
      const fakeSignature = new Uint8Array(256).fill(1); 

      console.group("%c☠️ ATTACK SIMULATION: Man-in-the-Middle (MITM)", "color: orange; font-size: 14px; font-weight: bold;");
      console.log("1. TARGET:", selectedUser);
      console.log("2. GENERATING FAKE IDENTITY (Mallory)...");
      console.log("   -> Fake Public Key Generated.");
      console.log("3. FORGING SIGNATURE...");
      console.log("   -> Real Private Key: [MISSING]");
      console.log("   -> Fake Signature Injected.");
      console.log("4. ACTION: Sending Malicious Handshake Offer...");
      console.groupEnd();

      // 3. Send offer as the sender but with anothers key + bad signature
      socketRef.current.emit('secure_signal', {
        targetUser: selectedUser,
        type: 'OFFER',
        payload: {
          ephemeralPub: malloryPub,
          signature: Array.from(fakeSignature) 
        }
      });
      alert("MITM Attack Launched! Check Victim's Screen.");
    };

    return (
      <div style={{ 
        display: 'flex', 
        height: '100%', 
        background: 'linear-gradient(135deg, #1e293b 0%, #334155 100%)', 
        borderRadius: '12px', 
        color: 'white',
        boxShadow: '0 8px 32px rgba(0, 0, 0, 0.3)',
        overflow: 'hidden'
      }}>
      
        {/* LEFT SIDEBAR: ALL USERS */}
        <div style={{ 
          width: '280px', 
          background: 'rgba(15, 23, 42, 0.6)', 
          padding: '20px', 
          borderRight: '1px solid rgba(148, 163, 184, 0.2)', 
          overflowY: 'auto',
          backdropFilter: 'blur(10px)'
        }}>
          <h3 style={{ 
            margin: '0 0 20px 0', 
            fontSize: '1.2em', 
            fontWeight: '600',
            color: '#f1f5f9',
            borderBottom: '2px solid rgba(59, 130, 246, 0.5)',
            paddingBottom: '10px'
          }}>
            Contacts
          </h3>
          {allUsers.length === 0 ? (
            <p style={{ color: '#94a3b8', textAlign: 'center', marginTop: '40px' }}>No contacts found.</p>
          ) : (
            allUsers.map(u => {
              const isOnline = onlineUsers.includes(u.username);
              const isSelected = selectedUser === u.username;
              return (
                <div key={u._id} onClick={() => startChat(u.username)}
                  style={{
                    padding: '14px',
                    cursor: 'pointer',
                    background: isSelected 
                      ? 'linear-gradient(135deg, #3b82f6 0%, #2563eb 100%)' 
                      : 'rgba(51, 65, 85, 0.4)',
                    marginBottom: '8px',
                    borderRadius: '10px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    transition: 'all 0.3s ease',
                    border: isSelected ? '1px solid rgba(59, 130, 246, 0.5)' : '1px solid rgba(148, 163, 184, 0.1)',
                    boxShadow: isSelected ? '0 4px 12px rgba(59, 130, 246, 0.3)' : 'none'
                  }}
                  onMouseOver={(e) => {
                    if (!isSelected) {
                      e.currentTarget.style.background = 'rgba(51, 65, 85, 0.7)';
                      e.currentTarget.style.transform = 'translateX(4px)';
                    }
                  }}
                  onMouseOut={(e) => {
                    if (!isSelected) {
                      e.currentTarget.style.background = 'rgba(51, 65, 85, 0.4)';
                      e.currentTarget.style.transform = 'translateX(0)';
                    }
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <div style={{
                      fontSize: '1.5em',
                      background: isOnline ? 'linear-gradient(135deg, #10b981 0%, #059669 100%)' : 'rgba(148, 163, 184, 0.3)',
                      borderRadius: '50%',
                      width: '40px',
                      height: '40px',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      boxShadow: isOnline ? '0 0 12px rgba(16, 185, 129, 0.4)' : 'none'
                    }}>
                      👤
                    </div>
                    <span style={{ fontWeight: isSelected ? '600' : '500', fontSize: '0.95em' }}>
                      {u.username}
                    </span>
                  </div>
                  {/* STATUS INDICATOR */}
                  <div style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px'
                  }}>
                    <div style={{
                      width: '10px', 
                      height: '10px', 
                      borderRadius: '50%',
                      backgroundColor: isOnline ? '#10b981' : '#64748b',
                      boxShadow: isOnline ? '0 0 8px #10b981' : 'none',
                      animation: isOnline ? 'pulse 2s infinite' : 'none'
                    }}></div>
                  </div>
                </div>
              );
            })
          )}
        </div>

        <div style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
          {incomingOffer && (
            <div style={{ 
              background: 'linear-gradient(135deg, #fbbf24 0%, #f59e0b 100%)', 
              padding: '16px 20px', 
              display: 'flex', 
              justifyContent: 'space-between', 
              alignItems: 'center',
              boxShadow: '0 4px 12px rgba(251, 191, 36, 0.3)',
              borderBottom: '1px solid rgba(245, 158, 11, 0.5)'
            }}>
              <span style={{ fontSize: '1em', fontWeight: '600', color: '#78350f' }}>
                🔔 <strong>{incomingOffer.sender}</strong> wants to chat.
              </span>
              <button 
                onClick={acceptChat} 
                style={{ 
                  background: 'linear-gradient(135deg, #10b981 0%, #059669 100%)', 
                  color: 'white', 
                  border: 'none', 
                  padding: '10px 20px',
                  borderRadius: '8px',
                  fontWeight: '600',
                  cursor: 'pointer',
                  boxShadow: '0 2px 8px rgba(16, 185, 129, 0.4)',
                  transition: 'all 0.3s ease'
                }}
                onMouseOver={(e) => e.target.style.transform = 'translateY(-2px)'}
                onMouseOut={(e) => e.target.style.transform = 'translateY(0)'}
              >
                Accept & Confirm Key
              </button>
            </div>
          )}

          {!selectedUser ? (
            <div style={{ 
              flex: 1, 
              padding: '40px', 
              color: '#94a3b8', 
              display: 'flex', 
              alignItems: 'center', 
              justifyContent: 'center',
              flexDirection: 'column',
              gap: '20px'
            }}>
              <div style={{ fontSize: '4em', opacity: '0.3' }}>💬</div>
              <div style={{ fontSize: '1.2em', fontWeight: '500' }}>
                Select a contact to view history or start chatting
              </div>
            </div>
          ) : (
            <>
              {/* Chat Header */}
              <div style={{ 
                padding: '18px 24px', 
                background: secureMode 
                  ? 'linear-gradient(135deg, #10b981 0%, #059669 100%)' 
                  : 'linear-gradient(135deg, #64748b 0%, #475569 100%)', 
                color: 'white', 
                display: 'flex', 
                justifyContent: 'space-between',
                alignItems: 'center',
                boxShadow: '0 4px 12px rgba(0, 0, 0, 0.2)',
                borderBottom: '1px solid rgba(255, 255, 255, 0.1)'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <div style={{
                    background: 'rgba(255, 255, 255, 0.2)',
                    borderRadius: '50%',
                    width: '40px',
                    height: '40px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: '1.3em'
                  }}>
                    👤
                  </div>
                  <span style={{ fontSize: '1.1em', fontWeight: '600' }}>
                    {selectedUser}
                  </span>
                </div>
                <span style={{ 
                  fontSize: '0.85em', 
                  padding: '6px 14px', 
                  background: 'rgba(255, 255, 255, 0.2)', 
                  borderRadius: '20px',
                  fontWeight: '600',
                  backdropFilter: 'blur(10px)',
                  border: '1px solid rgba(255, 255, 255, 0.3)'
                }}>
                  {secureMode ? "🔒 SECURE (HKDF+AES)" : (isSelectedUserOnline() ? "⚠️ NOT CONNECTED" : "❌ USER OFFLINE")}
                </span>
              </div>
            
              {/* Messages Area */}
              <div style={{ 
                flex: 1, 
                padding: '24px', 
                background: 'rgba(15, 23, 42, 0.4)', 
                overflowY: 'auto',
                backdropFilter: 'blur(10px)'
              }}>
                {messages.length === 0 && !secureMode && isSelectedUserOnline() && (
                  <div style={{ 
                    textAlign: 'center', 
                    marginTop: '40px', 
                    color: '#94a3b8',
                    padding: '30px',
                    background: 'rgba(51, 65, 85, 0.3)',
                    borderRadius: '12px',
                    border: '2px dashed rgba(148, 163, 184, 0.3)'
                  }}>
                    <div style={{ fontSize: '3em', marginBottom: '15px', opacity: '0.5' }}>🔐</div>
                    <p style={{ fontSize: '1.1em', fontWeight: '500' }}>
                      Click the user to start a Secure Handshake
                    </p>
                  </div>
                )}
                {messages.map((msg, i) => (
                  <div key={i} style={{ 
                    marginBottom: '12px', 
                    textAlign: msg.isSystem ? 'center' : (msg.isSelf ? 'right' : 'left'),
                    animation: 'slideIn 0.3s ease'
                  }}>
                    <div style={{
                      display: 'inline-block',
                      padding: '12px 16px',
                      borderRadius: '12px',
                      background: msg.isSystem 
                        ? 'rgba(100, 116, 139, 0.3)' 
                        : msg.isSelf 
                          ? 'linear-gradient(135deg, #3b82f6 0%, #2563eb 100%)' 
                          : 'rgba(51, 65, 85, 0.6)',
                      color: 'white',
                      border: msg.isSystem ? 'none' : '1px solid rgba(148, 163, 184, 0.2)',
                      maxWidth: '70%',
                      boxShadow: msg.isSystem ? 'none' : '0 2px 8px rgba(0, 0, 0, 0.2)',
                      backdropFilter: 'blur(10px)',
                      wordBreak: 'break-word'
                    }}>
                      {msg.isFile ? (
                        <div>
                          {msg.fileType.startsWith('image/') ? (
                            <img src={msg.fileData} alt="upload" style={{ 
                              maxWidth: '100%', 
                              borderRadius: '8px',
                              boxShadow: '0 4px 12px rgba(0, 0, 0, 0.3)'
                            }} />
                          ) : (
                            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                              <span style={{ fontSize: '2em' }}>📄</span>
                              <span>{msg.fileName}</span>
                            </div>
                          )}
                          <a 
                            href={msg.fileData} 
                            download={msg.fileName} 
                            style={{ 
                              display: 'block', 
                              marginTop: '8px', 
                              fontSize: '0.85em', 
                              color: 'rgba(255, 255, 255, 0.9)',
                              textDecoration: 'none',
                              padding: '6px 12px',
                              background: 'rgba(255, 255, 255, 0.2)',
                              borderRadius: '6px',
                              textAlign: 'center',
                              fontWeight: '600'
                            }}
                          >
                            ⬇ Download
                          </a>
                        </div>
                      ) : (
                        <span style={{ fontSize: '0.95em' }}>{msg.text}</span>
                      )}
                    </div>
                  </div>
                ))}
              </div>

              {/* INPUT AREA: Only enabled if Secure Mode is ON */}
              <div style={{ 
                padding: '20px 24px', 
                borderTop: '1px solid rgba(148, 163, 184, 0.2)', 
                display: 'flex', 
                alignItems: 'center',
                gap: '12px',
                background: 'rgba(15, 23, 42, 0.6)',
                backdropFilter: 'blur(10px)'
              }}>
                <label style={{ 
                  cursor: secureMode ? 'pointer' : 'not-allowed', 
                  fontSize: '1.5em', 
                  opacity: secureMode ? 1 : 0.4,
                  transition: 'all 0.3s ease',
                  padding: '8px 12px',
                  background: secureMode ? 'rgba(59, 130, 246, 0.2)' : 'transparent',
                  borderRadius: '8px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center'
                }}>
                  📎 
                  <input 
                    type="file" 
                    onChange={handleFileSelect} 
                    disabled={!secureMode} 
                    style={{ display: 'none' }} 
                  />
                </label>
                <input
                  disabled={!secureMode}
                  type="text"
                  value={inputText}
                  onChange={(e) => setInputText(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && sendMessage()}
                  placeholder={secureMode ? "Type a secure message..." : (isSelectedUserOnline() ? "Handshake required..." : "User is offline")}
                  style={{ 
                    flex: 1, 
                    padding: '12px 16px', 
                    borderRadius: '8px', 
                    border: '1px solid rgba(148, 163, 184, 0.3)',
                    background: secureMode ? 'rgba(255, 255, 255, 0.95)' : 'rgba(100, 116, 139, 0.3)',
                    color: secureMode ? '#1e293b' : '#94a3b8',
                    fontSize: '0.95em',
                    outline: 'none',
                    transition: 'all 0.3s ease'
                  }}
                />
                <button 
                  disabled={!secureMode} 
                  onClick={sendMessage} 
                  style={{ 
                    padding: '12px 24px', 
                    backgroundColor: secureMode ? '#3b82f6' : '#64748b', 
                    color: 'white', 
                    border: 'none', 
                    borderRadius: '8px',
                    fontWeight: '600',
                    cursor: secureMode ? 'pointer' : 'not-allowed',
                    transition: 'all 0.3s ease',
                    boxShadow: secureMode ? '0 4px 12px rgba(59, 130, 246, 0.3)' : 'none'
                  }}
                  onMouseOver={(e) => { if (secureMode) e.target.style.transform = 'translateY(-2px)'; }}
                  onMouseOut={(e) => { if (secureMode) e.target.style.transform = 'translateY(0)'; }}
                >
                  Send
                </button>
              
                {/* DEMO BUTTONS */}
                <button
                  disabled={!secureMode}
                  onClick={async () => {
                    if (messages.length === 0) return alert("Send a message first!");
                   
                    const lastMsg = messages[messages.length - 1];
                    if (!lastMsg || !lastMsg.text) return alert("Send a text message first!");

                    // 1. Use OLD Sequence Number (The Attack)
                    mySequenceRef.current -= 1;
                   
                    // 2. Add Timestamp (Required by new protocol)
                    const timestamp = Date.now();
                   
                    // 3. Construct Payload: Seq + Time + Msg
                    const payload = `${mySequenceRef.current}|||${timestamp}|||${lastMsg.text}`;
                   
                    const { ciphertext, iv } = await encryptData(payload, sessionKeyRef.current);
                   
                    // Restore sequence so normal chat continues working
                    mySequenceRef.current += 1;

                    console.log(`☠️ LAUNCHING REPLAY ATTACK with Seq ${mySequenceRef.current - 1}...`);
                    socketRef.current.emit('encrypted_message', { targetUser: selectedUser, ciphertext, iv });
                  }}
                  style={{ 
                    background: secureMode ? 'linear-gradient(135deg, #ef4444 0%, #dc2626 100%)' : '#64748b', 
                    color: 'white', 
                    border: 'none', 
                    padding: '12px 20px', 
                    cursor: secureMode ? 'pointer' : 'not-allowed',
                    borderRadius: '8px',
                    fontWeight: '600',
                    boxShadow: secureMode ? '0 4px 12px rgba(239, 68, 68, 0.3)' : 'none',
                    transition: 'all 0.3s ease'
                  }}
                  onMouseOver={(e) => { if (secureMode) e.target.style.transform = 'translateY(-2px)'; }}
                  onMouseOut={(e) => { if (secureMode) e.target.style.transform = 'translateY(0)'; }}
                >
                  🔄 Replay Attack
                </button>
                <button 
                  onClick={launchMITMAttack} 
                  style={{ 
                    background: 'linear-gradient(135deg, #f59e0b 0%, #d97706 100%)', 
                    color: 'white', 
                    border: 'none', 
                    padding: '12px 20px', 
                    borderRadius: '8px',
                    fontWeight: '600',
                    cursor: 'pointer',
                    boxShadow: '0 4px 12px rgba(245, 158, 11, 0.3)',
                    transition: 'all 0.3s ease'
                  }}
                  onMouseOver={(e) => e.target.style.transform = 'translateY(-2px)'}
                  onMouseOut={(e) => e.target.style.transform = 'translateY(0)'}
                >
                  ⚠️ MITM Attack
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    );
  }

export default Chat;