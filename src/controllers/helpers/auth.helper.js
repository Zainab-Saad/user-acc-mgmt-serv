import { getUserById, createUser } from '../../services/user.service.js';
import { sendVerificationEmail } from '../../utils/email.util.js';

export const getUserData = async (id) => {
  const userData = await getUserById(id);
  const clonedUserObject = Object.assign({}, userData);
  delete clonedUserObject.password;
  return clonedUserObject;
};

export const createUserData = async (email, password, firstName, lastName) => {
  const user = await createUser(email, password, firstName, lastName);
  sendVerificationEmail(firstName + ' ' + lastName, email);
  return user;
};
