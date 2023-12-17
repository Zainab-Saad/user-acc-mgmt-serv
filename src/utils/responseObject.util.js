export const resSuccess = (res, message, data = {}, status = 200) => {
  return res.status(status).json({
    success: true,
    message,
    data
  });
};

export const resFailure = (res, message, data = {}, status = 400) => {
  return res.status(status).json({
    success: false,
    message,
    data
  });
};
