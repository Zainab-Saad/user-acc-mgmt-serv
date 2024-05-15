import { v4 } from 'uuid';
import { assert } from 'chai';
import { Prisma } from '@prisma/client';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import crypto from 'crypto';
dotenv.config();

import { db } from '../src/utils/db.util.js';
import { getUserByEmail } from '../src/services/user.service.js';
import {
  createUserData,
  getUserData
} from '../src/controllers/helpers/auth.helper.js';
import {
  generateAccessToken,
  generateEmailVerificationToken,
  generateRefreshToken,
  verifyAccessToken,
  verifyEmailVerificationToken,
  verifyRefreshToken
} from '../src/utils/jwt.util.js';
import { hashToken } from '../src/utils/hashToken.util.js';

const data = {
  email: 'zainab101saad567@gmail.com',
  password: 'password1234',
  firstName: 'Zainab',
  lastName: 'Saad'
};

const data1 = {
  email: 'zainab_saad567@gmail.com',
  password: 'password1234',
  firstName: 'Zainab',
  lastName: 'Saad'
};

const data2 = {
  email: 'zainab123saad567@gmail.com',
  password: 'password1234',
  firstName: '',
  lastName: ''
};

const data3 = {
  email: 'zainab1001saad567@gmail.com',
  password: 'password1234',
  firstName: '',
  lastName: ''
};

const data4 = {
  email: 123456,
  password: 'password1234',
  firstName: true,
  lastName: false
};

const data5 = {
  email: 'zainab.saad567@gmail.com',
  password: 'password1234',
  firstName: 'Zainab',
  lastName: 'Saad'
};

// create an actual user in the db
await db.user.create({
  data
});

describe('User Authentication', function () {
  it('1. getUserByEmail with registered user email', async function () {
    const userActual = await getUserByEmail(data.email);
    const userExpected = await db.user.findUnique({
      where: {
        email: data.email
      }
    });
    assert.deepEqual(userActual, userExpected);
  });

  it('2. getUserByEmail with unregistered user email', async function () {
    const userActual = await getUserByEmail(data1.email);
    assert.isNull(userActual);
  });

  it('3. createUserData with already registered user email, correct password', async function () {
    try {
      await createUserData(
        data.email,
        data.password,
        data.firstName,
        data.lastName
      );
      assert.fail(
        'Expected error not thrown on creating user with the same email'
      );
    } catch (error) {
      assert.isTrue(error instanceof Prisma.PrismaClientKnownRequestError);
    }
  });

  it('4. createUserData with unregistered user email, empty password', async function () {
    try {
      await createUserData(data1.email, '', data1.firstName, data1.lastName);
      assert.fail(
        'Expected error not thrown on creating user with the empty password'
      );
    } catch (error) {
      if (error instanceof Prisma.PrismaClientValidationError) {
        assert.isTrue(error instanceof Prisma.PrismaClientValidationError);
      }
      assert.equal(
        error,
        'Expected error not thrown on creating user with the empty first and last name'
      );
    }
  });

  it('5. createUserData with unregistered user email, not strong password', async function () {
    try {
      await createUserData(
        data2.email,
        '1234',
        data2.firstName,
        data2.lastName
      );
      assert.fail(
        'Expected error not thrown on creating user with the weak password'
      );
    } catch (error) {
      if (error instanceof Prisma.PrismaClientValidationError) {
        assert.isTrue(error instanceof Prisma.PrismaClientValidationError);
      }
      assert.equal(
        error,
        'Expected error not thrown on creating user with the empty first and last name'
      );
    }
  });

  it('6. createUserData with unregistered user email, strong password, empty first and last name', async function () {
    try {
      await createUserData(
        data3.email,
        data3.password,
        data3.firstName,
        data3.lastName
      );
      assert.fail(
        'Expected error not thrown on creating user with the empty first and last name'
      );
    } catch (error) {
      if (error instanceof Prisma.PrismaClientValidationError) {
        assert.isTrue(error instanceof Prisma.PrismaClientValidationError);
      }
      assert.equal(
        error,
        'Expected error not thrown on creating user with the empty first and last name'
      );
    }
  });

  it('7. createUserData with numeric values for email, password, first and last name', async function () {
    try {
      await createUserData(
        data4.email,
        data4.password,
        data4.firstName,
        data4.lastName
      );
      assert.fail(
        'Expected error not thrown on creating user with the numeric entries'
      );
    } catch (error) {
      if (error instanceof Prisma.PrismaClientValidationError) {
        assert.isTrue(error instanceof Prisma.PrismaClientValidationError);
      }
      assert.throw(
        'Expected error not thrown on creating user with the empty first and last name'
      );
    }
  });

  it('8. createUserData with unregistered user email, strong password, correct first and last name', async function () {
    const userActual = await createUserData(
      data5.email,
      data5.password,
      data5.firstName,
      data5.lastName
    );
    const userExpected = await db.user.findUnique({
      where: {
        email: data5.email
      }
    });
    assert.deepEqual(userActual, userExpected);
  });

  it('9. generateAccessToken with null as user and jwtid', async function () {
    try {
      generateAccessToken(null);
    } catch (error) {
      assert.equal(error.message, 'User object can not be null');
    }
  });

  it('11. generateAccessToken with registered user email', async function () {
    const user = getUserByEmail(data.email);
    const accessToken = generateAccessToken(user);
    const decoded = jwt.verify(accessToken, process.env.JWT_ACCESS_SECRET);

    assert.equal(decoded.userId, user.id);
  });

  it('12. generateAccessToken with two different registered user objects, different tokens should be generated', async function () {
    const user1 = getUserByEmail(data.email);
    const user2 = getUserByEmail(data5.email);

    const accessToken1 = generateAccessToken(user1);
    const accessToken2 = generateAccessToken(user1);

    const decoded1 = jwt.verify(accessToken1, process.env.JWT_ACCESS_SECRET);
    const decoded2 = jwt.verify(accessToken2, process.env.JWT_ACCESS_SECRET);

    assert.equal(decoded1.userId, user1.id);
    assert.equal(decoded2.userId, user2.id);

    assert.notEqual(decoded1, decoded2);
  });

  it('13. generateRefreshToken with null user email, jwtid', async function () {
    try {
      generateRefreshToken(null, null);
    } catch (error) {
      assert.equal(error.message, 'User object or jwtid can not be null');
    }
  });

  it('14. generateRefreshToken with registered user email, correct jwtid', async function () {
    const jwtid = v4();
    const user = getUserByEmail(data.email);
    const refreshToken = generateRefreshToken(user, jwtid);
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

    assert.equal(decoded.userId, user.id);
    assert.equal(decoded.jwtid, jwtid);
  });

  it('15. generateRefreshToken with two different registered user objects, different tokens should be generated', async function () {
    const user1 = getUserByEmail(data.email);
    const user2 = getUserByEmail(data5.email);

    const jwtid1 = v4();
    const jwtid2 = v4();

    const refreshToken1 = generateRefreshToken(user1, jwtid1);
    const refreshToken2 = generateRefreshToken(user1, jwtid2);

    const decoded1 = jwt.verify(refreshToken1, process.env.JWT_REFRESH_SECRET);
    const decoded2 = jwt.verify(refreshToken2, process.env.JWT_REFRESH_SECRET);

    assert.equal(decoded1.userId, user1.id);
    assert.equal(decoded2.userId, user2.id);

    assert.equal(decoded1.jwtid, jwtid1);
    assert.equal(decoded2.jwtid, jwtid2);

    assert.notEqual(decoded1, decoded2);
  });

  it('16. generateRefreshToken with registered user email, random string as jwtid', async function () {
    try {
      const user = getUserByEmail(data.email);
      const randomjwt = 'hello-world';
      generateRefreshToken(user, randomjwt);
    } catch (error) {
      assert.equal(error.message, 'Invalid jwtid provided - expected a uuid');
    }
  });

  it('17. getUserData with registered user email, random int as jwtid', async function () {
    try {
      const user = getUserByEmail(data.email);
      const randomjwt = 12345;
      generateAccessToken(user, randomjwt);
    } catch (error) {
      assert.equal(error.message, 'Invalid jwtid provided - expected a uuid');
    }
  });

  it('18. getUserData with non existent user id in the database', async function () {
    const user = await getUserData(10000);
    assert.isEmpty(user);
  });

  it('19. getUserData with existent user id in the database', async function () {
    const user = await db.user.findUnique({
      where: {
        email: data.email
      }
    });
    const userById = await getUserData(user.id);
    assert.equal(user.id, userById.id);
    assert.equal(user.email, userById.email);
    assert.equal(user.firstName, userById.firstName);
    assert.equal(user.lastName, userById.lastName);
  });

  it('20. getUserData with string user id', async function () {
    try {
      await getUserData('Hello-world');
    } catch (error) {
      assert.isTrue(error instanceof Prisma.PrismaClientValidationError);
    }
  });

  it('21. getUserData with floating  number as user id', async function () {
    try {
      await getUserData(1.999);
    } catch (error) {
      assert.isTrue(error instanceof Prisma.PrismaClientValidationError);
    }
  });

  it('22. verifyRefreshToken with null as json web token', async function () {
    try {
      verifyRefreshToken(null);
    } catch (error) {
      assert.equal(error.message, 'Json web token can not be null');
    }
  });

  it('23. verifyRefreshToken with correct json web token newly generated', async function () {
    const jwtid = v4();
    const user = getUserByEmail(data.email);
    const refreshToken = generateRefreshToken(user, jwtid);

    const token = verifyRefreshToken(refreshToken);
    assert.equal(token.userId, user.id);
    assert.equal(token.jwtid, jwtid);
  });

  it('24. verifyRefreshToken with expired json web token -- THIS TEST WILL PASS AFTER 24HR', async function () {
    try {
      const refreshToken =
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjYsImp3dGlkIjoiZTNhN2JlYmItYzlhMS00NTIwLTkwMWItNDY5MzVmM2RjYTZlIiwiaWF0IjoxNzE1NzU2OTExLCJleHAiOjE3MTU4NDMzMTF9.Oqg3fjWRzlqcXeA8AR8Q4UuRbfe6A-uOj4X9rgwAxQY';
      verifyRefreshToken(refreshToken);
    } catch (error) {
      assert.equal(error.message, 'TokenExpiredError');
    }
  });

  it('25. verifyRefreshToken with random string as json web token', async function () {
    try {
      const refreshToken = 'hello-world';
      verifyRefreshToken(refreshToken);
    } catch (error) {
      assert.equal(error.message, 'Unauthorized');
    }
  });

  it('26. hashToken with null as the json web token', async function () {
    try {
      hashToken(null);
    } catch (error) {
      assert.equal(error.message, 'Token can not be null');
    }
  });

  it('27. hashToken with a valid json web token', async function () {
    const jwtid = v4();
    const user = getUserByEmail(data.email);
    const refreshToken = generateRefreshToken(user, jwtid);

    const tokenHash = hashToken(refreshToken);

    const expectedHash = crypto
      .createHash('sha512')
      .update(refreshToken)
      .digest('hex');

    assert.equal(tokenHash, expectedHash);
  });

  it('28. verifyAccessToken with null as json web token', async function () {
    try {
      verifyAccessToken(null);
    } catch (error) {
      assert.equal(error.message, 'Json web token can not be null');
    }
  });

  it('29. verifyAccessToken with correct json web token newly generated', async function () {
    const user = getUserByEmail(data.email);
    const accessToken = generateAccessToken(user);

    const token = verifyAccessToken(accessToken);
    assert.equal(token.userId, user.id);
  });

  it('31. verifyAccessToken with expired json web token', async function () {
    try {
      const accessToken =
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjYsImlhdCI6MTcxNTc1NjkxMSwiZXhwIjoxNzE1NzU3MjExfQ.UVOsqVyMWhYAmQvGKc80Uh1p0QKxjhpEPM9rY2wMDHc';
      verifyAccessToken(accessToken);
    } catch (error) {
      assert.equal(error.message, 'TokenExpiredError');
    }
  });

  it('32. verifyAccessToken with random string as json web token', async function () {
    try {
      const accessToken = 'hello-world';
      verifyAccessToken(accessToken);
    } catch (error) {
      assert.equal(error.message, 'Unauthorized');
    }
  });

  it('33. generateEmailVerificationToken with null email', async function () {
    try {
      generateEmailVerificationToken(null);
    } catch (error) {
      assert.equal(error.message, 'Email provided can not be null');
    }
  });

  it('34. generateEmailVerificationToken with registered email', async function () {
    const verificationToken = generateEmailVerificationToken(data.email);

    const expectedToken = jwt.sign(
      { email: data.email },
      process.env.JWT_EMAIL_VERIFICATION_SECRET,
      {
        expiresIn: '24h'
      }
    );

    assert.equal(verificationToken, expectedToken);
  });

  it('35. verifyEmailVerificationToken with null as json web token', async function () {
    try {
      verifyEmailVerificationToken(null);
    } catch (error) {
      assert.equal(error.message, 'Json web token can not be null');
    }
  });

  it('36. verifyEmailVerificationToken with correct json web token newly generated', async function () {
    const expectedToken = jwt.sign(
      { email: data.email },
      process.env.JWT_EMAIL_VERIFICATION_SECRET,
      {
        expiresIn: '24h'
      }
    );

    const verifiedToken = verifyEmailVerificationToken(expectedToken);

    assert.equal(verifiedToken.email, data.email);
  });

  it('37. verifyEmailVerificationToken with expired json web token', async function () {
    try {
      const emailToken =
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InphaW5hYi5zYWFkNTY3QGdtYWlsLmNvbSIsImlhdCI6MTcxNTcwNzQ4OCwiZXhwIjoxNzE1NzkzODg4fQ.jVS0J0hpIo6Qyi6A4AVxkaP3P_LREfrZc7_ABcoX280';
      verifyEmailVerificationToken(emailToken);
    } catch (error) {
      assert.equal(error.message, 'TokenExpiredError');
    }
  });

  it('38. verifyEmailVerificationToken with random string as json web token', async function () {
    try {
      const emailToken = 'hello-world';
      verifyEmailVerificationToken(emailToken);
    } catch (error) {
      assert.equal(
        error.message,
        'Error occured while verifying the email, please try again'
      );
    }
  });
});
