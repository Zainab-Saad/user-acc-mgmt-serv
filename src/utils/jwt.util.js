import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
dotenv.config();
export const generateAccessToken = (user) => {
  return jwt.sign(
    {
      userId: user.id
    },
    process.env.JWT_ACCESS_SECRET,
    {
      expiresIn: '5m'
    }
  );
};

export const generateRefreshToken = (user, jwtid) => {
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
  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user, jwtid);
  return {
    accessToken,
    refreshToken
  };
};

export const verifyAccessToken = (token) => {
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
  return jwt.sign({ email }, process.env.JWT_EMAIL_VERIFICATION_SECRET, {
    expiresIn: '24h'
  });
};

export const verifyEmailVerificationToken = (token) => {
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
