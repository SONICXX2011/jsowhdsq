const crypto = require('crypto');
const fs = require('fs');

function main() {
    console.log('[1] Reading agent/agent.js...');
    const src = fs.readFileSync('agent/agent.js');
    console.log('    Size: ' + src.length + ' bytes');

    console.log('[2] Generating AES-256 key + IV...');
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);

    console.log('[3] Encrypting AES-256-CBC...');
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    const enc = Buffer.concat([cipher.update(src), cipher.final()]);
    console.log('    Encrypted: ' + enc.length + ' bytes');

    console.log('[4] Filling bootstrap template...');
    let tpl = fs.readFileSync('agent/bootstrap.js', 'utf8');

    const placeholders = ['__KEY_HEX__', '__IV_HEX__', '__DATA_B64__', '__PLAIN_SIZE__'];
    for (const ph of placeholders) {
        if (tpl.indexOf(ph) === -1) {
            throw new Error('Missing placeholder: ' + ph);
        }
    }

    tpl = tpl.replace(/"__KEY_HEX__"/g, JSON.stringify(key.toString('hex')));
    tpl = tpl.replace(/"__IV_HEX__"/g, JSON.stringify(iv.toString('hex')));
    tpl = tpl.replace(/"__DATA_B64__"/g, JSON.stringify(enc.toString('base64')));
    tpl = tpl.replace(/__PLAIN_SIZE__/g, String(src.length));

    fs.writeFileSync('agent/final.js', tpl);
    console.log('[5] Wrote agent/final.js (' + tpl.length + ' bytes)');
    console.log('[OK] Ready for Fripack');
}

try { main(); } catch (e) { console.error('[ERR] ' + e.message); process.exit(1); }