const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const User = require('./models/User');
const { logEvent } = require('./logger'); 

const app = express();
const server = http.createServer(app);

app.use(cors());
app.use(express.json());

// 1. DB Connection
mongoose.connect('mongodb://127.0.0.1:27017/securechat')
  .then(() => logEvent("SYSTEM", "MongoDB Connected"))
  .catch(err => logEvent("SYSTEM_ERROR", { error: err.message }));

// 2. Real-Time Socket Setup
const io = new Server(server, {
  cors: {
    origin: "http://localhost:5173",
    methods: ["GET", "POST"]
  },
  maxHttpBufferSize: 1e8 // Limit of Socket Size
});

// 3. API Routes
app.post('/register', async (req, res) => {
  try {
    const { username, password, publicKeyECDH, publicKeyRSA } = req.body;
    
    // Generate 2FA Secret
    const twoFactorSecret = Math.floor(100000 + Math.random() * 900000).toString();
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      username,
      password: hashedPassword,
      twoFactorSecret,
      publicKeyECDH,
      publicKeyRSA
    });

    await newUser.save();
    
    logEvent("AUTH_REGISTER", { username, status: "SUCCESS" });
    
    res.status(201).json({ message: "User registered", twoFactorSecret });
  } catch (error) {
    logEvent("AUTH_REGISTER_FAIL", { error: error.message });
    res.status(400).json({ error: "Registration failed" });
  }
});

app.post('/login', async (req, res) => {
    try {
        const { username, password, twoFactorCode } = req.body;
        const user = await User.findOne({ username });
        
        if(!user) {
            logEvent("AUTH_LOGIN_FAIL", { username, reason: "User not found" });
            return res.status(404).json({error: "User not found"});
        }

        const validPass = await bcrypt.compare(password, user.password);
        if(!validPass) {
            logEvent("AUTH_LOGIN_FAIL", { username, reason: "Bad Password" });
            return res.status(401).json({error: "Invalid credentials"});
        }

        // 2FA Check
        if (user.twoFactorSecret !== twoFactorCode) {
             logEvent("AUTH_2FA_FAIL", { username });
             return res.status(403).json({ error: "Invalid 2FA Security Code!" });
        }

        logEvent("AUTH_LOGIN_SUCCESS", { username });
        
        res.json({ 
            username: user.username,
            publicKeyECDH: user.publicKeyECDH,
            publicKeyRSA: user.publicKeyRSA
        });
    } catch(e) {
        res.status(500).json({error: "Server error"});
    }
});

app.get('/user/:username', async (req, res) => {
  try {
    const user = await User.findOne({ username: req.params.username });
    if (!user) return res.status(404).json({ error: "User not found" });
    
    logEvent("KEY_FETCH", { requestFor: req.params.username });
    
    res.json({
      username: user.username,
      publicKeyECDH: user.publicKeyECDH,
      publicKeyRSA: user.publicKeyRSA
    });
  } catch (e) {
    res.status(500).json({ error: "Server error" });
  }
});

// Client-Side Security Reporting Endpoint
app.post('/report-security', (req, res) => {
  const { eventType, details } = req.body;
  // Log the security incident received from the client
  logEvent(`CLIENT_ALERT: ${eventType}`, details);
  res.status(200).send("Logged");
});

// Fetch All Users (The "Phonebook")
app.get('/users', async (req, res) => {
  try {
      // Return only usernames
      const users = await User.find({}, 'username'); 
      res.json(users);
  } catch (e) {
      res.status(500).json({ error: "Failed to fetch users" });
  }
});

// 4. Socket Handlers
const onlineUsers = new Map(); 

io.on('connection', (socket) => {
  socket.on('join', (username) => {
    onlineUsers.set(username, socket.id);
    socket.username = username; 
    io.emit('online_users_update', Array.from(onlineUsers.keys()));
    logEvent("USER_CONNECT", { username, ip: socket.handshake.address });
  });

  socket.on('secure_signal', ({ targetUser, type, payload }) => {
    const targetSocketId = onlineUsers.get(targetUser);
    if (targetSocketId) {
      io.to(targetSocketId).emit('secure_signal', {
        sender: socket.username,
        type,
        payload
      });
      logEvent("PROTOCOL_SIGNAL", { from: socket.username, to: targetUser, type });
    }
  });

  socket.on('encrypted_message', (data) => {
     const { targetUser, ciphertext, iv, isFile, fileName, fileType, fileId, chunkIndex, totalChunks } = data;
     const targetSocketId = onlineUsers.get(targetUser);
     
     if(targetSocketId) {
         io.to(targetSocketId).emit('encrypted_message', {
             sender: socket.username,
             ciphertext,
             iv,
             isFile,    
             fileName,
            fileType,
             fileId,
             chunkIndex,
             totalChunks
         });
         logEvent("MSG_RELAY", { 
             from: socket.username, 
             to: targetUser, 
             hasFile: !!isFile,
             payloadSize: ciphertext ? ciphertext.length : 0
         });
     }
  });

  socket.on('disconnect', () => {
    if(socket.username) {
        if (onlineUsers.get(socket.username) === socket.id) {
            onlineUsers.delete(socket.username);
            io.emit('online_users_update', Array.from(onlineUsers.keys()));
            logEvent("USER_DISCONNECT", { username: socket.username });
        }
    }
  });
});

const PORT = 3001;
server.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  logEvent("SYSTEM", "Server Started");
});