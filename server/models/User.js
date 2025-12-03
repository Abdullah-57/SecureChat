const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true }, 
  
  // 2FA Secret 
  twoFactorSecret: { type: String, required: true },

  // Identity Keys (Public Only)
  publicKeyECDH: { type: String, required: true }, 
  publicKeyRSA: { type: String, required: true },  
  
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('User', UserSchema);