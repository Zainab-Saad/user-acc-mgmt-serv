import { check } from 'express-validator';
import { resFailure } from '../../utils/responseObject.util.js';
export const registerValidator = [
  check('email', 'Email cannot be undefined').notEmpty(),
  check('email', 'Email is not valid').isEmail(),
  check('password', 'Password cannot be undefined').notEmpty(),
  check(
    'password',
    'Invalid Password, The password  should have 1. Minimum length of 8 characters. 2. At least one digit (0-9). 3. At least one letter'
  ).matches(/^(?=.*\d)(?=.+[a-z])(?=.+[A-Z])[0-9a-zA-Z]{8,}$/, 'i'),
  check('firstName', 'First Name cannot be undefined').notEmpty(),
  check('lastName', 'Last Name cannot be undefined').notEmpty()
];

export const loginValidator = [
  check('email', 'Email cannot be undefined').notEmpty(),
  check('email', 'Email is not valid').isEmail(),
  check('password', 'Password cannot be undefined').notEmpty(),
  check(
    'password',
    'Invalid Password, The password  should have 1. Minimum length of 8 characters. 2. At least one digit (0-9). 3. At least one letter'
  ).matches(/^(?=.*\d)(?=.+[a-z])(?=.+[A-Z])[0-9a-zA-Z]{8,}$/, 'i')
];

export const logoutValidator = [
  check('userId', 'user id cannot be undefined').notEmpty().isNumeric()
];

export const tokenValidator = (req, res, next) => {
  if (!req.headers.authorization.split(' ')[1]) {
    return resFailure(res, 'Authorization header not provided', {}, 403);
  }
  next();
};
