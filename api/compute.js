// api/compute.js
import crypto from 'crypto';

export default async function handler(req, res) {
  // 只允許 POST 請求
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  try {
    const { text, targetIterations, pubKey } = req.body;

    // 1. 在 Vercel 雲端伺服器端進行重運算（例如 PBKDF2 或加密）
    const salt = crypto.randomBytes(16).toString('hex');
    const derivedKey = crypto.pbkdf2Sync(text, salt, targetIterations || 100000, 32, 'sha256');

    // 2. 回傳雲端算力運算後的結果給前端
    return res.status(200).json({
      status: 'success',
      cloudServer: 'Vercel-Serverless-Node',
      saltHex: salt,
      derivedKeyHex: derivedKey.toString('hex'),
      message: '雲端天道算力已成功推演完畢！'
    });

  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
}
