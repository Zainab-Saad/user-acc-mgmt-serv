import express from 'express';

import {
  registerValidator,
  loginValidator,
  tokenValidator,
  logoutValidator
} from '../middlewares/validators/auth.validator.js';
import { validateResult } from '../utils/validationResult.util.js';
import {
  getMe,
  getPublicKeyOfServer,
  loginUser,
  refreshToken,
  registerUser,
  symmetricKey,
  verifyEmailVerificationToken_
} from '../controllers/auth.controller.js';
import {
  hasAuthToken,
  revokeAllRefreshTokens
} from '../middlewares/auth/auth.middleware.js';

export const authRouter = express.Router();

authRouter.post('/register', registerValidator, validateResult, registerUser);
authRouter.post('/login', loginValidator, validateResult, loginUser);
authRouter.post(
  '/refresh-token',
  hasAuthToken,
  tokenValidator,
  validateResult,
  refreshToken
);
authRouter.post(
  '/logout',
  logoutValidator,
  validateResult,
  revokeAllRefreshTokens
);

authRouter.get('/verify/:token', verifyEmailVerificationToken_);

authRouter.get('/get-me', hasAuthToken, getMe);

authRouter.get('/public-key', getPublicKeyOfServer);

authRouter.post('/exchange-key', symmetricKey);