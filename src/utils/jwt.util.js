import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { validate } from 'uuid';
dotenv.config();
export const generateAccessToken = (user) => {
  if (!user) {
    throw new Error('User object can not be null');
  }
  return jwt.sign(
    {
      userId: user.id
    },
    process.env.JWT_ACCESS_SECRET,
    {
      expiresIn: '2h'
    }
  );
};

export const generateRefreshToken = (user, jwtid) => {
  if (!user || !jwtid) {
    throw new Error('User object or jwtid can not be null');
  }

  if (!validate(jwtid)) {
    throw new Error('Invalid jwtid provided - expected a uuid');
  }

  return jwt.sign(
    {
      userId: user.id,
      jwtid
    },
    process.env.JWT_REFRESH_SECRET,
    {
      expiresIn: '24h'
    }
  );
};

export const generateTokens = (user, jwtid) => {
  if (!user || !jwtid) {
    throw new Error('User object or jwtid can not be null');
  }

  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user, jwtid);
  return {
    accessToken,
    refreshToken
  };
};

export const verifyAccessToken = (token) => {
  if (!token) {
    throw new Error('Json web token can not be null');
  }
  try {
    return jwt.verify(token, process.env.JWT_ACCESS_SECRET);
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      throw new Error(err.name);
    }
    throw new Error('Unauthorized');
  }
};

export const verifyRefreshToken = (token) => {
  if (!token) {
    throw new Error('Json web token can not be null');
  }
  try {
    return jwt.verify(token, process.env.JWT_REFRESH_SECRET);
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      throw new Error(err.name);
    }
    throw new Error('Unauthorized');
  }
};

export const generateEmailVerificationToken = (email) => {
  if (!email) {
    throw new Error('Email provided can not be null');
  }
  return jwt.sign({ email }, process.env.JWT_EMAIL_VERIFICATION_SECRET, {
    expiresIn: '24h'
  });
};

export const verifyEmailVerificationToken = (token) => {
  if (!token) {
    throw new Error('Json web token can not be null');
  }
  try {
    return jwt.verify(token, process.env.JWT_EMAIL_VERIFICATION_SECRET);
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      throw new Error('Your token has expired, please try again');
    }
    throw new Error(
      'Error occured while verifying the email, please try again'
    );
  }
};
