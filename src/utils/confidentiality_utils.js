import fs from 'fs';
import crypto from 'crypto';
import path from 'path';

export const generateNonce = () => {
  const newNonce = crypto.randomBytes(16).toString('hex'); // Generate a random nonce
  return newNonce; // Return the generated nonce
};

export const readSymmetricKey = () => {
  const filePath = path.resolve('./symmetric_key_server.txt');
  const keyHex = fs.readFileSync(filePath, 'utf-8').trim();
  return Buffer.from(keyHex, 'hex'); // Convert hex string to Buffer
};

// Function to encrypt data using AES
export const encryptData = (data, key) => {
  const iv = crypto.randomBytes(16); // Generate a random initialization vector (IV)
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);

  const encrypted = Buffer.concat([
    cipher.update(JSON.stringify(data), 'utf8'),
    cipher.final(),
  ]);

  return {
    iv: iv.toString('hex'), // Return the IV as a hex string
    encryptedData: encrypted.toString('hex'), // Return encrypted data as hex string
  };
};

export const resSuccessEncrypted = (res, message, data) => {
    try {
      const symmetricKey = readSymmetricKey(); // Read the symmetric key from the file
      const encryptedResponse = encryptData(data, symmetricKey); // Encrypt the data
  
      res.json({
        success: true,
        message,
        data: encryptedResponse, // Send encrypted data
      });
    } catch (error) {
      console.error('Error encrypting response:', error.message);
      res.status(500).json({
        success: false,
        message: 'Failed to encrypt response data.',
      });
    }
  };