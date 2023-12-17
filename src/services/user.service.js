import bcrypt from 'bcrypt';
import { db } from '../utils/db.util.js';

export const createUser = async (email, password, firstName, lastName) => {
  const hashedPassword = await bcrypt.hash(password, 10);
  return await db.user.create({
    data: {
      email,
      password: hashedPassword,
      firstName,
      lastName
    }
  });
};

export const getUserByEmail = async (email) => {
  return await db.user.findUnique({
    where: {
      email
    }
  });
};

export const getUserById = async (id) => {
  return await db.user.findUnique({
    where: {
      id
    }
  });
};

export const updateUserVerificationStatus = async (email) => {
  return await db.user.update({
    where: {
      email
    },
    data: {
      isEmailVerified: true
    }
  });
};
