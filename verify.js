// api/verify.js - Vercel Serverless 後端 API
const crypto = require('crypto');

module.exports = async (req, res) => {
    // 跨域與請求方法檢查
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') return res.status(200).end();
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method Not Allowed' });

    try {
        const { cipherText, saltHex, nonce, text, targetPrefix } = req.body;

        // 1. 後端實時驗證 PoW 是否有效
        const testString = `${saltHex}_${nonce}_${text}`;
        const hash = crypto.createHash('sha256').update(testString).digest('hex');

        if (!hash.startsWith(targetPrefix)) {
            return res.status(400).json({ success: false, message: '天道驗證失敗：PoW Nonce 試棋無效！' });
        }

        // 2. 伺服器端 HMAC 簽章加固 (使用環境變數中的 SERVER_PEPPER)
        const serverPepper = process.env.SERVER_PEPPER || "INK_SECRET_PEPPER_2026";
        const hmacSign = crypto.createHmac('sha256', serverPepper)
                               .update(cipherText)
                               .digest('hex');

        const armoredCipher = `${cipherText}.SERVER_SIG_${hmacSign.substring(0, 16)}`;

        return res.status(200).json({
            success: true,
            message: "後端天道陣法驗證通過！已追加伺服器端 HMAC 簽章加固。",
            armoredCipher: armoredCipher,
            signature: hmacSign.substring(0, 16)
        });

    } catch (error) {
        return res.status(500).json({ error: 'Server Internal Error: ' + error.message });
    }
};
