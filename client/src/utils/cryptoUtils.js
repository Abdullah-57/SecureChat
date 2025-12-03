/* 1. KEY GENERATION 
  We generate two pairs:
  - ECDH (P-256): For creating the shared session secret (Speed).
  - RSA-PSS (2048): For signing messages to prove identity (Anti-MITM).
*/

export const generateIdentityKeys = async () => {
    // 1. ECDH Key Pair (for encryption)
    const ecdhPair = await window.crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      false, // Private key must be non-extractable!
      ["deriveKey", "deriveBits"]
    );
  
    // 2. RSA Key Pair (for signing/authentication)
    const rsaPair = await window.crypto.subtle.generateKey(
      {
        name: "RSA-PSS",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      false,
      ["sign", "verify"]
    );
  
    return { ecdhPair, rsaPair };
  };
  
/* 2. EXPORTING KEYS 
  We need to send Public Keys to the server. Private keys stay local.
*/
  export const exportKey = async (key) => {
    const exported = await window.crypto.subtle.exportKey("spki", key);
    return  window.btoa(String.fromCharCode(...new Uint8Array(exported)));
  };
  
  export const importKey = async (pem, type) => {
    // Helper to convert base64 back to key object
    const binaryDerString = window.atob(pem);
    const binaryDer = new Uint8Array(binaryDerString.length);
    for (let i = 0; i < binaryDerString.length; i++) {
      binaryDer[i] = binaryDerString.charCodeAt(i);
    }
    
    if (type === "ECDH") {
      return await window.crypto.subtle.importKey(
        "spki",
        binaryDer.buffer,
        { name: "ECDH", namedCurve: "P-256" },
        true,
        []
      );
    } else if (type === "RSA") {
       return await window.crypto.subtle.importKey(
        "spki",
        binaryDer.buffer,
        { name: "RSA-PSS", hash: "SHA-256" },
        true,
        ["verify"]
      );
    }
  };
  
/* 3. SHARED SECRET DERIVATION (ECDH)
  Combine My Private Key + Their Public Key = Shared Secret
*/
  export const deriveSharedSecret = async (myPrivateKey, theirPublicKey) => {
    return await window.crypto.subtle.deriveBits(
      { name: "ECDH", public: theirPublicKey },
      myPrivateKey,
      256
    );
  };
  
/* 4. SESSION KEY CREATION
  Turn the shared secret into a usable AES-GCM key
*/
/* UPGRADE: HKDF KEY DERIVATION 
  Instead of using raw bits, we use HKDF to create a cryptographically perfect Session Key.
*/

  // 1. Helper: Convert Shared Secret Bits to a Master Key
  const importMasterKey = async (rawBits) => {
    return await window.crypto.subtle.importKey(
      "raw",
      rawBits,
      { name: "HKDF" }, 
      false, 
      ["deriveKey", "deriveBits"]
    );
  };

  // 2. The New Session Key Generator
  export const deriveSessionKey = async (sharedBits) => {
    // Import raw bits as an HKDF Master Key
    const masterKey = await importMasterKey(sharedBits);

    // Derive the AES-GCM Key using HKDF-SHA256
    // This ensures the key is uniformly distributed and secure.
    const aesKey = await window.crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: new Uint8Array(),
        info: new TextEncoder().encode("SecureChat_Session_v1") 
      },
      masterKey,
      { name: "AES-GCM", length: 256 }, // AES-256
      true, 
      ["encrypt", "decrypt"]
    );

    return aesKey;
  };
  
  /*
    5. ENCRYPTION (AES-GCM)
    Used for Chat Messages and Files.
    Returns: Ciphertext + IV
  */
  export const encryptData = async (data, sessionKey) => {
    const iv = window.crypto.getRandomValues(new Uint8Array(12)); // Random IV (Mandatory)
    const encodedData = new TextEncoder().encode(data);
  
    const ciphertext = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      sessionKey,
      encodedData
    );
  
    // Pack IV and Ciphertext together
    return {
      iv: Array.from(iv), // Send as array for JSON compatibility
      ciphertext: Array.from(new Uint8Array(ciphertext))
    };
  };
  
/*
  6. DECRYPTION (AES-GCM)
*/
  export const decryptData = async (encryptedObj, sessionKey) => {
    const iv = new Uint8Array(encryptedObj.iv);
    const ciphertext = new Uint8Array(encryptedObj.ciphertext);
  
    try {
      const decrypted = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        sessionKey,
        ciphertext
      );
      return new TextDecoder().decode(decrypted);
    } catch (e) {
      console.error("Decryption Failed - Possible Tampering");
      throw e;
    }
  };
  
/*
  7. DIGITAL SIGNATURES (RSA-PSS)
  To prevent MITM.
*/
  export const signData = async (data, privateKey) => {
    const enc = new TextEncoder().encode(data);
    const signature = await window.crypto.subtle.sign(
      { name: "RSA-PSS", saltLength: 32 },
      privateKey,
      enc
    );
    return Array.from(new Uint8Array(signature));
  };
  
  export const verifySignature = async (data, signature, publicKey) => {
    const enc = new TextEncoder().encode(data);
    return await window.crypto.subtle.verify(
      { name: "RSA-PSS", saltLength: 32 },
      publicKey,
      new Uint8Array(signature),
      enc
    );
  };

/* 8. BINARY ENCRYPTION (For Files) 
  Difference: We do NOT use TextEncoder. We use raw ArrayBuffers.
*/
export const encryptFile = async (fileBuffer, sessionKey) => {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    
    const ciphertext = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      sessionKey,
      fileBuffer // Encrypt raw bytes directly
    );
  
    return {
      iv: Array.from(iv),
      ciphertext: Array.from(new Uint8Array(ciphertext))
    };
  };
  
  export const decryptFile = async (encryptedObj, sessionKey) => {
    const iv = new Uint8Array(encryptedObj.iv);
    const ciphertext = new Uint8Array(encryptedObj.ciphertext);
  
    try {
      const decryptedBuffer = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        sessionKey,
        ciphertext
      );
      return decryptedBuffer; // Returns ArrayBuffer (to be made into Blob)
    } catch (e) {
      console.error("File Decryption Failed");
      throw e;
    }
  };

  /* KEY CONFIRMATION HELPER */
export const computeKeyHash = async (sessionKey) => {
  // Export key to bytes
  const rawKey = await window.crypto.subtle.exportKey("raw", sessionKey);
  // Hash it
  const hashBuffer = await window.crypto.subtle.digest("SHA-256", rawKey);
  // Convert to String for easy comparison
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
};