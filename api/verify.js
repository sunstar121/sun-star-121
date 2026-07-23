// api/verify.js - Vercel Serverless 後端運算模組
const crypto = require('crypto'); // 使用 Node.js 原生模組，不需要額外 npm install

module.exports = async (req, res) => {
    // 跨域設定 (CORS)
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method Not Allowed' });
    }

    try {
        const { cipherText, nonce, saltHex, text, targetPrefix } = req.body || {};

        // 1. 後端驗證前端傳來的 PoW 是否真實（防作假）
        const testString = `${saltHex}_${nonce}_${text}`;
        const hash = crypto.createHash('sha256').update(testString).digest('hex');

        if (targetPrefix && !hash.startsWith(targetPrefix)) {
            return res.status(400).json({ 
                success: false, 
                message: '天道驗證失敗：PoW Nonce 試棋無效！' 
            });
        }

        // 2. 伺服器端 HMAC 二次加固簽章
        const serverPepper = process.env.SERVER_PEPPER || "INK_SECRET_PEPPER_2026";
        const hmacSign = crypto.createHmac('sha256', serverPepper)
                               .update(cipherText || "")
                               .digest('hex');

        const armoredCipher = `${cipherText}.SERVER_SIG_${hmacSign.substring(0, 16)}`;

        // 3. 回傳運算結果給前端
        return res.status(200).json({
            success: true,
            message: "【天道後端】驗證通過！已追加伺服器端 HMAC 簽章加固。",
            armoredCipher: armoredCipher,
            signature: hmacSign.substring(0, 16),
            serverHash: hash
        });

    } catch (error) {
        return res.status(500).json({ error: 'Server Error: ' + error.message });
    }
};
