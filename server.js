const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

app.get('/', (req, res) => {
    res.send('🐉 水墨終端 v2.4 雲端算力引擎運作中...');
});

app.post('/api/pow-encrypt', (req, res) => {
    try {
        const { text, targetPrefix = '00', pubKeyBase64 } = req.body;
        
        if (!text || !pubKeyBase64) {
            return res.status(400).json({ error: '缺少必要參數' });
        }

        const startTime = Date.now();
        const saltHex = crypto.randomBytes(16).toString('hex');
        let nonce = 0;
        let foundHash = '';

        while (true) {
            nonce++;
            const testString = `${saltHex}_${nonce}_${text}`;
            const hash = crypto.createHash('sha256').update(testString).digest('hex');

            if (hash.startsWith(targetPrefix)) {
                foundHash = hash;
                break;
            }
        }

        const iv = crypto.randomBytes(12);
        const aesKey = crypto.randomBytes(32);
        
        const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
        const armoredPayload = `[POW:${foundHash}|NONCE:${nonce}]::${text}`;
        let encrypted = cipher.update(armoredPayload, 'utf8', 'base64');
        encrypted += cipher.final('base64');
        const authTag = cipher.getAuthTag().toString('base64');

        const cleanPubKey = pubKeyBase64.replace(/[\r\n\s]+/g, '');
        const bufferPubKey = Buffer.from(cleanPubKey, 'base64');
        const pemPubKey = `-----BEGIN PUBLIC KEY-----\n${bufferPubKey.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`;
        
        const encryptedAesKey = crypto.publicEncrypt(
            {
                key: pemPubKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256'
            },
            aesKey
        );

        const totalElapsed = ((Date.now() - startTime) / 1000).toFixed(2);
        const finalCipher = `INK_V2.4::${encryptedAesKey.toString('base64')}.${iv.toString('base64')}.${encrypted}.${authTag}`;

        res.json({
            success: true,
            cipherText: finalCipher,
            nonce: nonce,
            powHash: foundHash,
            elapsed: totalElapsed
        });
    } catch (err) {
        res.status(500).json({ error: '運算錯誤：' + err.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
});
