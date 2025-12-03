/**
 * Secure Chat Application - Server Entry Point
 * 
 * This server handles:
 * - User authentication (registration/login with 2FA)
 * - Real-time encrypted messaging via WebSockets
 * - Public key exchange for E2EE (End-to-End Encryption)
 * - Security event logging
 */

// ==================== Dependencies ====================
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const User = require('./models/User');
const { logEvent } = require('./logger'); 

// ==================== Express App Setup ====================
const app = express();
const server = http.createServer(app);

console.log('📦 Initializing Express middleware...');
app.use(cors()); // Enable Cross-Origin Resource Sharing
app.use(express.json()); // Parse JSON request bodies
console.log('✅ Express middleware configured');

// ==================== Database Connection ====================
console.log('🔌 Attempting to connect to MongoDB...');
mongoose.connect('mongodb://127.0.0.1:27017/securechat')
  .then(() => {
    console.log('✅ MongoDB connection established successfully');
    logEvent("SYSTEM", "MongoDB Connected");
  })
  .catch(err => {
    console.error('❌ MongoDB connection failed:', err.message);
    logEvent("SYSTEM_ERROR", { error: err.message });
  });

// ==================== Socket.IO Real-Time Setup ====================
console.log('🔌 Configuring Socket.IO server...');
const io = new Server(server, {
  cors: {
    origin: "http://localhost:5173", // Frontend URL
    methods: ["GET", "POST"]
  },
  maxHttpBufferSize: 1e8 // 100MB limit for file transfers
});
console.log('✅ Socket.IO server configured');

// ==================== REST API Routes ====================

/**
 * POST /register
 * Register a new user with public keys for E2EE
 * Returns: 2FA secret code for initial setup
 */
app.post('/register', async (req, res) => {
  console.log('📝 Registration request received');
  try {
    const { username, password, publicKeyECDH, publicKeyRSA } = req.body;
    console.log(`   Username: ${username}`);
    console.log(`   Has ECDH key: ${!!publicKeyECDH}`);
    console.log(`   Has RSA key: ${!!publicKeyRSA}`);
    
    // Generate 6-digit 2FA Secret (100000-999999)
    const twoFactorSecret = Math.floor(100000 + Math.random() * 900000).toString();
    console.log(`   Generated 2FA secret: ${twoFactorSecret}`);
    
    // Hash password with bcrypt (salt rounds: 10)
    const hashedPassword = await bcrypt.hash(password, 10);
    console.log('   Password hashed successfully');

    // Create new user document
    const newUser = new User({
      username,
      password: hashedPassword,
      twoFactorSecret,
      publicKeyECDH,
      publicKeyRSA
    });

    await newUser.save();
    console.log(`✅ User '${username}' registered successfully`);
    
    logEvent("AUTH_REGISTER", { username, status: "SUCCESS" });
    
    res.status(201).json({ message: "User registered", twoFactorSecret });
  } catch (error) {
    console.error(`❌ Registration failed: ${error.message}`);
    logEvent("AUTH_REGISTER_FAIL", { error: error.message });
    res.status(400).json({ error: "Registration failed" });
  }
});

/**
 * POST /login
 * Authenticate user with password and 2FA code
 * Returns: User data including public keys for E2EE
 */
app.post('/login', async (req, res) => {
    console.log('🔐 Login request received');
    try {
        const { username, password, twoFactorCode } = req.body;
        console.log(`   Username: ${username}`);
        console.log(`   2FA Code provided: ${!!twoFactorCode}`);
        
        // Find user in database
        const user = await User.findOne({ username });
        
        if(!user) {
            console.log(`❌ Login failed: User '${username}' not found`);
            logEvent("AUTH_LOGIN_FAIL", { username, reason: "User not found" });
            return res.status(404).json({error: "User not found"});
        }
        console.log(`   User found: ${username}`);

        // Verify password using bcrypt
        const validPass = await bcrypt.compare(password, user.password);
        if(!validPass) {
            console.log(`❌ Login failed: Invalid password for '${username}'`);
            logEvent("AUTH_LOGIN_FAIL", { username, reason: "Bad Password" });
            return res.status(401).json({error: "Invalid credentials"});
        }
        console.log('   Password verified');

        // Verify 2FA code matches stored secret
        if (user.twoFactorSecret !== twoFactorCode) {
             console.log(`❌ Login failed: Invalid 2FA code for '${username}'`);
             logEvent("AUTH_2FA_FAIL", { username });
             return res.status(403).json({ error: "Invalid 2FA Security Code!" });
        }
        console.log('   2FA code verified');

        console.log(`✅ Login successful for '${username}'`);
        logEvent("AUTH_LOGIN_SUCCESS", { username });
        
        // Return user data with public keys
        res.json({ 
            username: user.username,
            publicKeyECDH: user.publicKeyECDH,
            publicKeyRSA: user.publicKeyRSA
        });
    } catch(e) {
        console.error(`❌ Login error: ${e.message}`);
        res.status(500).json({error: "Server error"});
    }
});

/**
 * GET /user/:username
 * Fetch public keys for a specific user (for E2EE key exchange)
 * Returns: User's public keys (ECDH and RSA)
 */
app.get('/user/:username', async (req, res) => {
  console.log(`🔑 Public key fetch request for: ${req.params.username}`);
  try {
    const user = await User.findOne({ username: req.params.username });
    if (!user) {
      console.log(`❌ User '${req.params.username}' not found`);
      return res.status(404).json({ error: "User not found" });
    }
    
    console.log(`✅ Public keys retrieved for '${req.params.username}'`);
    logEvent("KEY_FETCH", { requestFor: req.params.username });
    
    res.json({
      username: user.username,
      publicKeyECDH: user.publicKeyECDH,
      publicKeyRSA: user.publicKeyRSA
    });
  } catch (e) {
    console.error(`❌ Error fetching user keys: ${e.message}`);
    res.status(500).json({ error: "Server error" });
  }
});

/**
 * POST /report-security
 * Client-side security event reporting endpoint
 * Used to log security incidents detected on the client side
 */
app.post('/report-security', (req, res) => {
  const { eventType, details } = req.body;
  console.log(`🚨 Security alert received: ${eventType}`);
  console.log(`   Details:`, details);
  // Log the security incident received from the client
  logEvent(`CLIENT_ALERT: ${eventType}`, details);
  res.status(200).send("Logged");
});

/**
 * GET /users
 * Fetch all registered usernames (for user directory/phonebook)
 * Returns: Array of user objects with username only
 */
app.get('/users', async (req, res) => {
  console.log('📋 User list request received');
  try {
      // Return only usernames (exclude sensitive data like passwords)
      const users = await User.find({}, 'username'); 
      console.log(`✅ Retrieved ${users.length} users`);
      res.json(users);
  } catch (e) {
      console.error(`❌ Error fetching users: ${e.message}`);
      res.status(500).json({ error: "Failed to fetch users" });
  }
});

// ==================== Socket.IO Event Handlers ====================
// Map to track online users: username -> socket.id
const onlineUsers = new Map(); 

console.log('👂 Setting up Socket.IO event listeners...');

/**
 * Socket.IO Connection Handler
 * Handles all real-time communication events
 */
io.on('connection', (socket) => {
  console.log(`🔌 New socket connection: ${socket.id}`);
  console.log(`   IP Address: ${socket.handshake.address}`);
  
  /**
   * Event: 'join'
   * User joins the chat system
   * Updates online users list and broadcasts to all clients
   */
  socket.on('join', (username) => {
    console.log(`👤 User '${username}' joining (socket: ${socket.id})`);
    onlineUsers.set(username, socket.id);
    socket.username = username; // Store username on socket for later use
    
    // Broadcast updated online users list to all connected clients
    const onlineList = Array.from(onlineUsers.keys());
    io.emit('online_users_update', onlineList);
    console.log(`   Online users: ${onlineList.length} - [${onlineList.join(', ')}]`);
    
    logEvent("USER_CONNECT", { username, ip: socket.handshake.address });
  });

  /**
   * Event: 'secure_signal'
   * Handles secure protocol signals (e.g., key exchange, handshake)
   * Relays signals between users for E2EE setup
   */
  socket.on('secure_signal', ({ targetUser, type, payload }) => {
    console.log(`📡 Secure signal received from '${socket.username}' to '${targetUser}'`);
    console.log(`   Signal type: ${type}`);
    
    const targetSocketId = onlineUsers.get(targetUser);
    if (targetSocketId) {
      // Forward signal to target user
      io.to(targetSocketId).emit('secure_signal', {
        sender: socket.username,
        type,
        payload
      });
      console.log(`✅ Signal relayed to '${targetUser}'`);
      logEvent("PROTOCOL_SIGNAL", { from: socket.username, to: targetUser, type });
    } else {
      console.log(`⚠️  Target user '${targetUser}' is offline`);
    }
  });

  /**
   * Event: 'encrypted_message'
   * Handles encrypted messages and file transfers
   * Relays encrypted data between users (server never decrypts - true E2EE)
   */
  socket.on('encrypted_message', (data) => {
     const { targetUser, ciphertext, iv, isFile, fileName, fileType, fileId, chunkIndex, totalChunks } = data;
     
     console.log(`📨 Encrypted message from '${socket.username}' to '${targetUser}'`);
     console.log(`   Is file: ${!!isFile}`);
     if (isFile) {
       console.log(`   File: ${fileName} (${fileType})`);
       console.log(`   Chunk: ${chunkIndex}/${totalChunks} (ID: ${fileId})`);
     }
     console.log(`   Payload size: ${ciphertext ? ciphertext.length : 0} bytes`);
     
     const targetSocketId = onlineUsers.get(targetUser);
     
     if(targetSocketId) {
         // Relay encrypted message to target user
         // Server never decrypts - maintaining true end-to-end encryption
         io.to(targetSocketId).emit('encrypted_message', {
             sender: socket.username,
             ciphertext,
             iv, // Initialization vector for AES decryption
             isFile,    
             fileName,
             fileType,
             fileId,
             chunkIndex,
             totalChunks
         });
         console.log(`✅ Message relayed to '${targetUser}'`);
         logEvent("MSG_RELAY", { 
             from: socket.username, 
             to: targetUser, 
             hasFile: !!isFile,
             payloadSize: ciphertext ? ciphertext.length : 0
         });
     } else {
         console.log(`⚠️  Target user '${targetUser}' is offline - message not delivered`);
     }
  });

  /**
   * Event: 'disconnect'
   * Handles user disconnection
   * Removes user from online list and broadcasts update
   */
  socket.on('disconnect', () => {
    console.log(`🔌 Socket disconnected: ${socket.id}`);
    if(socket.username) {
        // Verify this socket is still mapped to this username (prevent race conditions)
        if (onlineUsers.get(socket.username) === socket.id) {
            console.log(`👋 User '${socket.username}' disconnected`);
            onlineUsers.delete(socket.username);
            
            // Broadcast updated online users list
            const onlineList = Array.from(onlineUsers.keys());
            io.emit('online_users_update', onlineList);
            console.log(`   Remaining online users: ${onlineList.length} - [${onlineList.join(', ')}]`);
            
            logEvent("USER_DISCONNECT", { username: socket.username });
        } else {
            console.log(`   User '${socket.username}' already removed (duplicate disconnect)`);
        }
    } else {
        console.log(`   Socket disconnected before joining (no username)`);
    }
  });
});

console.log('✅ Socket.IO event handlers configured');

// ==================== Server Startup ====================
const PORT = 3001;
console.log(`🚀 Starting server on port ${PORT}...`);
server.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
  console.log(`📡 Socket.IO server ready for connections`);
  logEvent("SYSTEM", "Server Started");
});