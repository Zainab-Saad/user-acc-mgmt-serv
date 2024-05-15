import crypto from 'crypto';

export const hashToken = (token) => {
  if (!token) {
    throw new Error('Token can not be null');
  }
  return crypto.createHash('sha512').update(token).digest('hex');
};
