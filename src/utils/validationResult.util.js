import { validationResult } from 'express-validator';

export const validateResult = (req, res, next) => {
  const result = validationResult(req);
  if (!result.isEmpty()) {
    const errors = result.errors;
    res.status(400).json({
      success: false,
      message: errors[0]
    });
  } else {
    next();
  }
};
