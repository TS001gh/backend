import jwt from 'jsonwebtoken';

export default function generateAccessToken(userId) {
  return jwt.sign(userId, process.env.TOKEN_SECRET, { expiresIn: '1800s' });
}
