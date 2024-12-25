import { v4 } from 'uuid';
import bcrypt from 'bcrypt';
import fs from 'fs';
import crypto from 'crypto';
import path from 'path';

import { resSuccess, resFailure } from '../utils/responseObject.util.js';
import {
  getUserByEmail,
  getUserById,
  updateUserVerificationStatus
} from '../services/user.service.js';
import {
  generateTokens,
  verifyRefreshToken,
  verifyEmailVerificationToken,
  verifyAccessToken
} from '../utils/jwt.util.js';
import {
  addRefreshTokenToDb,
  deleteRefreshToken,
  getRefreshTokenById
} from '../services/auth.service.js';
import { hashToken } from '../utils/hashToken.util.js';

import { authErrors } from '../errors/auth.error.js';
import { createUserData, getUserData } from './helpers/auth.helper.js';
import {generateNonce, resSuccessEncrypted} from '../utils/confidentiality_utils.js';


const nonces = new Map(); // In-memory storage for simplicity; replace with a database for production.

export const registerUser = async (req, res, next) => {
  try {
    const { email, password, firstName, lastName } = req.body;

    const user = await getUserByEmail(email);

    if (user) {
      return resFailure(res, authErrors.EMAIL_ALREADY_REGISTERED);
    }

    createUserData(email, password, firstName, lastName);

    return resSuccess(res, 'User added to the system');
  } catch (err) {
    if (err.message === authErrors.INVALID_USER_TYPE) {
      return resFailure(res, authErrors.INVALID_USER_TYPE);
    }
  }
};

export const loginUser = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const user = await getUserByEmail(email);

    if (!user) {
      return resFailure(res, authErrors.EMAIL_NOT_REGISTERED, {}, 403);
    }

    if (!user.isEmailVerified) {
      return resFailure(res, authErrors.EMAIL_NOT_VERIFIED);
    }

    if (!(await bcrypt.compare(password, user.password))) {
      return resFailure(res, authErrors.INCORRECT_PASSWORD, {}, 403);
    }

    const jwtid = v4();
    const { accessToken, refreshToken } = generateTokens(user, jwtid);
    await addRefreshTokenToDb(jwtid, refreshToken, user.id);

    const newNonce = generateNonce();

    // Store the nonce and set an expiration time (e.g., 5 minutes)
    nonces.set(user.id, newNonce);

    const userData = await getUserData(user.id);

    return resSuccessEncrypted(res, 'Login Successful', {
      ...userData,
      accessToken,
      refreshToken,
      nonce: newNonce
    });
  } catch (err) {
    if (err.message === authErrors.INVALID_USER_TYPE) {
      return resFailure(res, authErrors.INVALID_USER_TYPE);
    }
    next(err);
  }
};

// this is for generating a new access and refresh token once the access token expires
export const refreshToken = async (req, res, next) => {
  try {
    const refreshTokenHeader = req.headers.authorization.split(' ')[1];
    const verifiedJwt = verifyRefreshToken(refreshTokenHeader);
    const existingRefreshToken = await getRefreshTokenById(verifiedJwt.jwtid);
    if (
      !existingRefreshToken ||
      existingRefreshToken.revoked === true ||
      hashToken(refreshTokenHeader) !== existingRefreshToken.hashedToken
    ) {
      // TODO delete these refresh tokens
      return resFailure(res, authErrors.UNAUTHORIZED, {}, 401);
    }
    const user = await getUserById(existingRefreshToken.userId);
    if (user.deletedAt) {
      // TODO delete these refresh tokens
      return resFailure(res, authErrors.UNAUTHORIZED, {}, 401);
    }

    await deleteRefreshToken(existingRefreshToken.id);
    const jwtid = v4();
    const { accessToken, refreshToken } = generateTokens(user, jwtid);
    await addRefreshTokenToDb(jwtid, refreshToken, user.id);
    return resSuccess(res, 'Token refeshed', {
      accessToken,
      refreshToken
    });
  } catch (err) {
    if (err.message === 'TokenExpiredError') {
      return resFailure(res, authErrors.TOKEN_EXPIRED, {}, 401);
    }
    return resFailure(res, authErrors.UNAUTHORIZED, {}, 401);
  }
};

export const verifyEmailVerificationToken_ = async (req, res, next) => {
  try {
    const { token } = req.params;
    const { email } = verifyEmailVerificationToken(token);

    const user = getUserByEmail(email);
    if (!user) {
      return resFailure(res, authErrors.EMAIL_NOT_REGISTERED);
    }

    if (user.isEmailVerified) {
      return resFailure(res, authErrors.EMAIL_ALREADY_VERIFIED);
    }
    await updateUserVerificationStatus(email);

    return resSuccess(res, 'Email Verified Successfully');
  } catch (err) {
    if (err.message === 'TokenExpiredError') {
      return resFailure(res, authErrors.TOKEN_EXPIRED, {}, 401);
    }
    return resFailure(res, authErrors.UNAUTHORIZED, {}, 401);
  }
};

// export const getMe = async (req, res, next) => {
//   try {
//     const accessToken = req.headers.authorization.split(' ')[1];
//     const verifiedAccessToken = verifyAccessToken(accessToken);
//     const user = await getUserById(verifiedAccessToken.userId);
//     if (!user) {
//       return resSuccess(res, authErrors.UNAUTHORIZED);
//     }

//     if (!user.isEmailVerified) {
//       return resFailure(res, authErrors.EMAIL_NOT_VERIFIED);
//     }

//     const userData = await getUserData(user.id);

//     return resSuccess(res, 'User data returned successfully', {
//       ...userData
//     });
//   } catch (err) {
//     if (err.message === 'TokenExpiredError') {
//       return resFailure(res, authErrors.TOKEN_EXPIRED, {}, 401);
//     } else if (err.message === authErrors.INVALID_USER_TYPE) {
//       return resFailure(res, authErrors.INVALID_USER_TYPE, {}, 401);
//     }
//     return resFailure(res, authErrors.UNAUTHORIZED, {}, 401);
//   }
// };


export const getMe = async (req, res, next) => {
  try {
    // Step 1: Retrieve the Authorization header
    const authorizationHeader = req.headers.authorization;
    if (!authorizationHeader) {
      return resFailure(res, authErrors.UNAUTHORIZED, {}, 401);
    }

    const [bearer, encryptedToken] = authorizationHeader.split(' ');
    if (bearer !== 'Bearer' || !encryptedToken) {
      return resFailure(res, authErrors.UNAUTHORIZED, {}, 401);
    }

    // Step 2: Retrieve the IV from the headers
    const iv = req.headers.iv;
    if (!iv) {
      return resFailure(res, authErrors.UNAUTHORIZED, {}, 401);
    }

    // Step 3: Load the symmetric key
    const symmetricKeyHex = fs.readFileSync('./symmetric_key_server.txt', 'utf-8');
    const symmetricKey = Buffer.from(symmetricKeyHex, 'hex');

    // Step 4: Decrypt the Authorization header data
    const decipher = crypto.createDecipheriv('aes-256-cbc', symmetricKey, Buffer.from(iv, 'hex'));
    let decryptedData = decipher.update(Buffer.from(encryptedToken, 'hex'));
    decryptedData = Buffer.concat([decryptedData, decipher.final()]);
    const decryptedString = decryptedData.toString('utf-8');

    // Step 5: Parse the decrypted data
    const [accessToken, receivedNonce] = decryptedString.split(':');
    if (!accessToken || !receivedNonce) {
      return resFailure(res, authErrors.UNAUTHORIZED, {}, 401);
    }

    console.log("Access Token:", accessToken)
    console.log("Syemmetric Key:", symmetricKey, symmetricKeyHex)
    console.log("Receoved Nonce", receivedNonce)


    console.log("Nonce set before: ")
    nonces.forEach((nonce, userId) => {
      console.log(`User ID: ${userId}, Nonce: ${nonce}`);
    });

    // Step 6: Validate the nonce
    const userId = verifyAccessToken(accessToken).userId;
    if (!nonces.has(userId) || nonces.get(userId) !== receivedNonce) {
      return resFailure(res, 'Invalid or expired nonce', {}, 400);
    }

    // Step 7: Remove the used nonce to prevent reuse
    nonces.delete(userId);

    console.log("Nonce set after: ")
    nonces.forEach((nonce, userId) => {
      console.log(`User ID: ${userId}, Nonce: ${nonce}`);
    });

    // Step 8: Fetch user data and send response
    const user = await getUserById(userId);
    if (!user || !user.isEmailVerified) {
      return resFailure(res, authErrors.UNAUTHORIZED, {}, 401);
    }

    const userData = await getUserData(user.id);

    return resSuccess(res, 'User data returned successfully', {
      ...userData,
    });
  } catch (err) {
    if (err.message === 'TokenExpiredError') {
      return resFailure(res, authErrors.TOKEN_EXPIRED, {}, 401);
    } else if (err.message === authErrors.INVALID_USER_TYPE) {
      return resFailure(res, authErrors.INVALID_USER_TYPE, {}, 401);
    }
    console.error('Error in getMe:', err.message);
    return resFailure(res, authErrors.UNAUTHORIZED, {}, 401);
  }
};

export const getPublicKeyOfServer = async (req, res, next) => {
  try {
    // Load the certificate (PEM format)
    const cert = fs.readFileSync('./self_signed_CA.pem', 'utf-8');

    // Extract the public key
    const publicKey = crypto.createPublicKey(cert);

    // Export the public key in PEM format
    const exportedPublicKey = publicKey.export({ type: 'spki', format: 'pem' });

    // Log the public key (optional for debugging)
    console.log('Public Key:', exportedPublicKey);

    // Return the public key as a string in the response
    return resSuccess(res, 'Public key retrieved successfully', { publicKey: exportedPublicKey });
    
  } catch (err) {
    console.error('Error retrieving public key:', err.message);
    return resFailure(res, 'Failed to retrieve public key', {}, 500);
  }
};

export const symmetricKey = async (req, res, next) => {
  const { encryptedKey } = req.body;

  try {
    // Load the encrypted private key from the .key file
    const privateKeyPem = fs.readFileSync('./self_signed_CA.key', 'utf-8');

    // Create the private key object with the passphrase
    const privateKey = crypto.createPrivateKey({
      key: privateKeyPem,
      format: 'pem',
      passphrase: 'zainab', // Replace with the actual passphrase for the private key
    });

    console.log('Private Key loaded successfully.');

    // Decrypt the symmetric key using the private key
    const symmetricKey = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      Buffer.from(encryptedKey, 'base64')
    );

    const symmetricKeyHex = symmetricKey.toString('hex');
    console.log('Decrypted Symmetric Key:', symmetricKeyHex);

    // Define the file path for storing the symmetric key
    const filePath = path.resolve('./symmetric_key_server.txt');
    
    console.log('Current Working Directory:', process.cwd());

    // Store the symmetric key in a file
    fs.writeFileSync(filePath, symmetricKeyHex, 'utf-8');

    // Log the absolute file path
    console.log(`Symmetric key saved to: ${filePath}`);

    res.send('Symmetric key exchange successful and key stored!');  } catch (error) {
    console.error('Error decrypting key:', error.message);
    res.status(500).send('Failed to decrypt the key.');
  }
};


// # TODO
// // Middleware to validate nonce
// const validateNonce = (req, res, next) => {
//   const { nonce, userId } = req.body;

//   if (!nonces.has(userId) || nonces.get(userId) !== nonce) {
//     return res.status(400).json({ success: false, message: 'Invalid or expired nonce.' });
//   }

//   // Remove the used nonce to prevent reuse
//   nonces.delete(userId);
//   next();
// };