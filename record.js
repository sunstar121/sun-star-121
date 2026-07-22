// api/record.js - 寫入 Supabase 資料庫 API
const { createClient } = require('@supabase/supabase-js');

// 初始化 Supabase 客戶端 (從 Vercel 環境變數讀取)
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_ANON_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

module.exports = async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') return res.status(200).end();
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method Not Allowed' });

    try {
        const { signature, levelTag, nonce } = req.body;

        // 寫入 Supabase 審計日誌表 (audit_logs)
        const { data, error } = await supabase
            .from('audit_logs')
            .insert([
                { 
                    signature: signature, 
                    level_tag: levelTag, 
                    nonce_count: nonce,
                    created_at: new Date().toISOString()
                }
            ]);

        if (error) throw error;

        return res.status(200).json({
            success: true,
            message: "加密審計日誌已成功寫入 Supabase 雲端資料庫！",
            data
        });

    } catch (error) {
        return res.status(500).json({ error: 'Supabase DB Write Error: ' + error.message });
    }
};
