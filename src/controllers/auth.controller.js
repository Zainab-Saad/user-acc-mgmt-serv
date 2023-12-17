import { v4 } from 'uuid';
import bcrypt from 'bcrypt';

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

    const userData = await getUserData(user.id);
    return resSuccess(res, 'Login Successful', {
      ...userData,
      accessToken,
      refreshToken
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

export const getMe = async (req, res, next) => {
  try {
    const accessToken = req.headers.authorization.split(' ')[1];
    const verifiedAccessToken = verifyAccessToken(accessToken);
    const user = await getUserById(verifiedAccessToken.userId);
    if (!user) {
      return resSuccess(res, authErrors.UNAUTHORIZED);
    }

    if (!user.isEmailVerified) {
      return resFailure(res, authErrors.EMAIL_NOT_VERIFIED);
    }

    const userData = await getUserData(user.id);

    return resSuccess(res, 'User data returned successfully', {
      ...userData
    });
  } catch (err) {
    if (err.message === 'TokenExpiredError') {
      return resFailure(res, authErrors.TOKEN_EXPIRED, {}, 401);
    } else if (err.message === authErrors.INVALID_USER_TYPE) {
      return resFailure(res, authErrors.INVALID_USER_TYPE, {}, 401);
    }
    return resFailure(res, authErrors.UNAUTHORIZED, {}, 401);
  }
};
