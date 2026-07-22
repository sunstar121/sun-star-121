// worker.js - 負責背景算力對弈與加密
self.onmessage = async function (e) {
    const { text, targetIterations, targetPrefix, saltHex, pubKeyBase64, levelTag } = e.data;
    const startTime = performance.now();

    try {
        // 1. PBKDF2 密鑰衍生
        const baseKeyMaterial = await crypto.subtle.importKey(
            "raw", 
            new TextEncoder().encode(text), 
            { name: "PBKDF2" }, 
            false, 
            ["deriveBits"]
        );
        const rawSalt = new Uint8Array(saltHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

        // 2. PoW 工作量證明算力碰撞
        let nonce = 0;
        let foundProof = false;
        let finalPowHash = "";

        while (!foundProof) {
            nonce++;
            const testString = `${saltHex}_${nonce}_${text}`;
            const hashBuffer = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(testString));
            const hashArray = new Uint8Array(hashBuffer);
            
            // 檢查前綴是否符合目標 (例如 000)
            let hashHex = Array.from(hashArray).map(b => b.toString(16).padStart(2, '0')).join('');
            if (hashHex.startsWith(targetPrefix)) {
                foundProof = true;
                finalPowHash = hashHex;
            }

            // 每 1000 次匯報一次進度給主介面
            if (nonce % 1000 === 0) {
                self.postMessage({ type: 'POW_PROGRESS', nonce, elapsed: ((performance.now() - startTime) / 1000).toFixed(2) });
            }
        }

        // 3. RSA + AES 混合加密
        const cleanPubKey = pubKeyBase64.replace(/[\r\n\s]+/g, "");
        const binaryPubKey = atob(cleanPubKey);
        const pubKeyBytes = new Uint8Array(binaryPubKey.length);
        for (let i = 0; i < binaryPubKey.length; i++) pubKeyBytes[i] = binaryPubKey.charCodeAt(i);

        const rsaPubKey = await crypto.subtle.importKey("spki", pubKeyBytes.buffer, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
        const aesKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
        const iv = crypto.getRandomValues(new Uint8Array(12));

        const armoredPayload = `[SEC_${levelTag}|POW:${finalPowHash}|NONCE:${nonce}]::${text}`;
        const aesEncrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, aesKey, new TextEncoder().encode(armoredPayload));

        const rawAesKey = await crypto.subtle.exportKey("raw", aesKey);
        const rsaEncryptedKey = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, rsaPubKey, rawAesKey);

        const ab2str = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
        const finalCipher = `INK_V2.4::${ab2str(rsaEncryptedKey)}.${ab2str(iv)}.${ab2str(aesEncrypted)}`;

        // 將完成結果回傳給主網頁
        self.postMessage({
            type: 'DONE',
            finalCipher,
            nonce,
            saltHex,
            text,
            targetPrefix,
            totalElapsed: ((performance.now() - startTime) / 1000).toFixed(2)
        });

    } catch (err) {
        self.postMessage({ type: 'ERROR', error: err.message || String(err) });
    }
};
