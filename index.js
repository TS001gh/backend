import express from 'express';
import cors from 'cors';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import prisma from './dbCon.js';
import bodyParser from 'body-parser';
import dotenv from 'dotenv';

import generateAccessToken from './lib/generateAccessToken.js';

dotenv.config();

const app = express();
const port = 5000;

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});

app.use(bodyParser.urlencoded({ extended: false }));

app.use(cors());
app.use(express.json());

app.use((error, req, res, next) => {
  res.send({ success: false, error: error.message });
});

app.get('/', async (req, res) => {
  const users = await prisma.user.findMany({
    select: {
      id: true,
      username: true,
    },
  });
  if (!users) {
    res.send({ success: false, data: 'there are not any user in db' });
  }
  res.send({ success: true, data: users });
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  const hashedPass = await bcrypt.hash(password, 10);

  try {
    if (!username || !password) {
      res.status(422).send({
        success: false,
        error: 'Please provide username and password',
      });
    }

    const checkUser = await prisma.user.findUnique({
      where: {
        username,
      },
    });

    if (checkUser) {
      res.send({ success: false, data: 'This user is exits' });
    }

    const user = await prisma.user.create({
      data: {
        username,
        password: hashedPass,
      },
    });

    const token = generateAccessToken({ userId: user.id });

    delete user.password;

    if (!user) {
      res.status(402).send({ success: false, error: 'registration failed' });
    }

    res.send({ success: true, data: { user, token } });
  } catch (error) {
    res.send({ success: false, error: error.message });
  }
});
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    if (!username || !password) {
      res.status(422).send({
        success: false,
        error: 'Please provide username and password',
      });
    }

    const user = await prisma.user.findFirst({
      where: {
        username,
      },
    });

    const pass_does_match = bcrypt.compare(user.password, password);

    const token = generateAccessToken({ userId: user.id });

    delete user.password;

    if (!pass_does_match) {
      res.status(402).send({ success: false, error: 'login proccess failed' });
    }

    res.send({ success: true, data: { user, token } });
  } catch (error) {
    res.send({ success: false, error: error.message });
  }
});

app.get('/user/token', async (req, res) => {
  try {
    console.log(req.headers);
    const token = req.headers.authorization.split(' ')[1];
    console.log(token);
    const payload = jwt.verify(token, process.env.TOKEN_SECRET);
    const { username } = payload;

    const user = await prisma.user.findFirst({
      where: {
        username,
      },
    });

    delete user.password;

    res.send({ success: true, data: user });
  } catch (error) {
    res.send({ success: false, error: error.message });
  }
});

app.use((req, res) => {
  res.send(' route doesnt found ');
});
