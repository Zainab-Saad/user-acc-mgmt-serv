import express from 'express';
import dotenv from 'dotenv';
import bodyParser from 'body-parser';
import cors from 'cors';

import { authRouter } from './routes/auth.route.js';

dotenv.config();
const app = express();
app.use(bodyParser.json());
app.use(cors());
app.use(authRouter);

const PORT = process.env.NODE_DOCKER_PORT;
app.listen(PORT, () => {
  console.info(`server running at port ${PORT}`);
});

export { app };
