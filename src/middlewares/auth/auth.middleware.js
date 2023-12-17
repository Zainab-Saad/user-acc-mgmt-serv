import { revokeRefreshTokens } from '../../services/auth.service.js';
import { verifyAccessToken } from '../../utils/jwt.util.js';
import { resFailure, resSuccess } from '../../utils/responseObject.util.js';
import { authErrors } from '../../errors/auth.error.js';

export const hasAuthToken = (req, res, next) => {
  if (!req.headers.authorization) {
    return resFailure(res, authErrors.INVALID_AUTH_HEADER, {}, 403);
  }
  next();
};

export const revokeAllRefreshTokens = async (req, res, next) => {
  try {
    const { userId } = req.body;
    await revokeRefreshTokens(parseInt(userId));
    return resSuccess(res, `All tokens revoked for userId: ${userId}`);
  } catch (err) {
    next(err);
  }
};

export const isAuthenticated = async (req, res, next) => {
  try {
    const token = req.headers.authorization.split(' ')[1];
    const verifiedToken = verifyAccessToken(token);
    req.payload = verifiedToken;
  } catch (err) {
    if (err.message === 'TokenExpiredError') {
      return resFailure(res, authErrors.TOKEN_EXPIRED, {}, 401);
    }
    return resFailure(res, authErrors.UNAUTHORIZED, {}, 401);
  }
};
