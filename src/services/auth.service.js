import { db } from '../utils/db.util.js';
import { hashToken } from '../utils/hashToken.util.js';

export const addRefreshTokenToDb = async (jwtid, refreshToken, userId) => {
  return await db.refreshToken.create({
    data: {
      id: jwtid,
      hashedToken: hashToken(refreshToken),
      userId
    }
  });
};

export const getRefreshTokenById = async (id) => {
  return await db.refreshToken.findUnique({
    where: {
      id
    }
  });
};

// soft delete of the refresh token
export const deleteRefreshToken = async (id) => {
  return await db.refreshToken.update({
    where: {
      id
    },
    data: {
      revoked: true
    }
  });
};

export const revokeRefreshTokens = async (userId) => {
  return await db.refreshToken.updateMany({
    where: {
      userId
    },
    data: {
      revoked: true
    }
  });
};
