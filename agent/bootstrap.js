(function () {
    'use strict';

    var AES_C = [
        "#include <stdint.h>",
        "#include <string.h>",
        "",
        "static uint8_t SBOX[256];",
        "static uint8_t INV_SBOX[256];",
        "static uint8_t RCON[15] = {0x8d,1,2,4,8,16,32,64,128,27,54,108,216,171,77};",
        "static int g_ready = 0;",
        "",
        "static void init_tables(void) {",
        "    uint8_t p = 1, q = 1;",
        "    if (g_ready) return;",
        "    do {",
        "        p = p ^ (p << 1) ^ ((p & 0x80) ? 0x1B : 0);",
        "        q ^= q << 1;",
        "        q ^= q << 2;",
        "        q ^= q << 4;",
        "        if (q & 0x80) q ^= 0x09;",
        "        uint8_t x = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) ^ ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4));",
        "        SBOX[p] = x ^ 0x63;",
        "        INV_SBOX[SBOX[p]] = p;",
        "    } while (p != 1);",
        "    SBOX[0] = 0x63;",
        "    INV_SBOX[0x63] = 0;",
        "    g_ready = 1;",
        "}",
        "",
        "static uint8_t gmul(uint8_t a, uint8_t b) {",
        "    uint8_t p = 0;",
        "    int i;",
        "    for (i = 0; i < 8; i++) {",
        "        if (b & 1) p ^= a;",
        "        uint8_t hi = a & 0x80;",
        "        a <<= 1;",
        "        if (hi) a ^= 0x1b;",
        "        b >>= 1;",
        "    }",
        "    return p;",
        "}",
        "",
        "static void key_expansion(const uint8_t *key, uint8_t *rkey) {",
        "    int Nk = 8, Nr = 14, i, j;",
        "    int total = 4 * (Nr + 1);",
        "    for (i = 0; i < Nk; i++) {",
        "        rkey[4*i]   = key[4*i];",
        "        rkey[4*i+1] = key[4*i+1];",
        "        rkey[4*i+2] = key[4*i+2];",
        "        rkey[4*i+3] = key[4*i+3];",
        "    }",
        "    for (i = Nk; i < total; i++) {",
        "        uint8_t t[4];",
        "        for (j = 0; j < 4; j++) t[j] = rkey[4*(i-1) + j];",
        "        if (i % Nk == 0) {",
        "            uint8_t tmp = t[0];",
        "            t[0] = SBOX[t[1]] ^ RCON[i / Nk];",
        "            t[1] = SBOX[t[2]];",
        "            t[2] = SBOX[t[3]];",
        "            t[3] = SBOX[tmp];",
        "        } else if (i % Nk == 4) {",
        "            for (j = 0; j < 4; j++) t[j] = SBOX[t[j]];",
        "        }",
        "        for (j = 0; j < 4; j++) rkey[4*i + j] = rkey[4*(i - Nk) + j] ^ t[j];",
        "    }",
        "}",
        "",
        "static void inv_cipher(const uint8_t *in, uint8_t *out, const uint8_t *rkey) {",
        "    int Nr = 14, round, c, i;",
        "    uint8_t s[16], t[16];",
        "    for (i = 0; i < 16; i++) s[i] = in[i] ^ rkey[Nr * 16 + i];",
        "    for (round = Nr - 1; round >= 1; round--) {",
        "        t[0]=s[0];  t[1]=s[13]; t[2]=s[10]; t[3]=s[7];",
        "        t[4]=s[4];  t[5]=s[1];  t[6]=s[14]; t[7]=s[11];",
        "        t[8]=s[8];  t[9]=s[5];  t[10]=s[2]; t[11]=s[15];",
        "        t[12]=s[12]; t[13]=s[9]; t[14]=s[6]; t[15]=s[3];",
        "        for (i = 0; i < 16; i++) s[i] = INV_SBOX[t[i]] ^ rkey[round * 16 + i];",
        "        for (c = 0; c < 4; c++) {",
        "            uint8_t a = s[c*4], b = s[c*4+1], cc = s[c*4+2], d = s[c*4+3];",
        "            s[c*4]   = gmul(a,14) ^ gmul(b,11) ^ gmul(cc,13) ^ gmul(d,9);",
        "            s[c*4+1] = gmul(a,9)  ^ gmul(b,14) ^ gmul(cc,11) ^ gmul(d,13);",
        "            s[c*4+2] = gmul(a,13) ^ gmul(b,9)  ^ gmul(cc,14) ^ gmul(d,11);",
        "            s[c*4+3] = gmul(a,11) ^ gmul(b,13) ^ gmul(cc,9)  ^ gmul(d,14);",
        "        }",
        "    }",
        "    t[0]=s[0];  t[1]=s[13]; t[2]=s[10]; t[3]=s[7];",
        "    t[4]=s[4];  t[5]=s[1];  t[6]=s[14]; t[7]=s[11];",
        "    t[8]=s[8];  t[9]=s[5];  t[10]=s[2]; t[11]=s[15];",
        "    t[12]=s[12]; t[13]=s[9]; t[14]=s[6]; t[15]=s[3];",
        "    for (i = 0; i < 16; i++) out[i] = INV_SBOX[t[i]] ^ rkey[i];",
        "}",
        "",
        "void aes_decrypt(uint8_t *out, const uint8_t *in, uint32_t len, const uint8_t *key, const uint8_t *iv) {",
        "    uint8_t rkey[240];",
        "    uint8_t prev[16];",
        "    uint32_t i;",
        "    int j;",
        "    init_tables();",
        "    key_expansion(key, rkey);",
        "    for (j = 0; j < 16; j++) prev[j] = iv[j];",
        "    for (i = 0; i < len; i += 16) {",
        "        uint8_t block[16];",
        "        inv_cipher(in + i, block, rkey);",
        "        for (j = 0; j < 16; j++) out[i + j] = block[j] ^ prev[j];",
        "        for (j = 0; j < 16; j++) prev[j] = in[i + j];",
        "    }",
        "}"
    ].join("\n");

    var KEY_HEX = "__KEY_HEX__";
    var IV_HEX = "__IV_HEX__";
    var DATA_B64 = "__DATA_B64__";
    var PLAIN_SIZE = __PLAIN_SIZE__;

    function hexToBytes(h) {
        var b = [];
        for (var i = 0; i < h.length; i += 2) b.push(parseInt(h.substr(i, 2), 16));
        return b;
    }

    function b64ToBytes(b64) {
        var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        var lookup = {};
        for (var i = 0; i < chars.length; i++) lookup[chars[i]] = i;
        var out = [], buf = 0, bits = 0;
        for (var j = 0; j < b64.length; j++) {
            var c = b64[j];
            if (c === '=') break;
            var v = lookup[c];
            if (v === undefined) continue;
            buf = (buf << 6) | v;
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out.push((buf >> bits) & 0xFF);
            }
        }
        return out;
    }

    function bytesToUtf8(bytes) {
        var out = '', i = 0;
        while (i < bytes.length) {
            var c = bytes[i++];
            if (c < 128) out += String.fromCharCode(c);
            else if (c < 224) out += String.fromCharCode(((c & 31) << 6) | (bytes[i++] & 63));
            else if (c < 240) out += String.fromCharCode(((c & 15) << 12) | ((bytes[i++] & 63) << 6) | (bytes[i++] & 63));
            else {
                var cp = ((c & 7) << 18) | ((bytes[i++] & 63) << 12) | ((bytes[i++] & 63) << 6) | (bytes[i++] & 63);
                cp -= 0x10000;
                out += String.fromCharCode(0xD800 + (cp >> 10), 0xDC00 + (cp & 1023));
            }
        }
        return out;
    }

    try {
        var encBytes = b64ToBytes(DATA_B64);
        var keyBytes = hexToBytes(KEY_HEX);
        var ivBytes = hexToBytes(IV_HEX);

        var inBuf = Memory.alloc(encBytes.length);
        var outBuf = Memory.alloc(encBytes.length);
        var keyBuf = Memory.alloc(32);
        var ivBuf = Memory.alloc(16);

        for (var i = 0; i < encBytes.length; i++) inBuf.add(i).writeU8(encBytes[i]);
        for (var i = 0; i < 32; i++) keyBuf.add(i).writeU8(keyBytes[i]);
        for (var i = 0; i < 16; i++) ivBuf.add(i).writeU8(ivBytes[i]);

        var cm = new CModule(AES_C);
        var decryptFn = new NativeFunction(cm.aes_decrypt, 'void',
            ['pointer', 'pointer', 'uint32', 'pointer', 'pointer']);

        decryptFn(outBuf, inBuf, encBytes.length, keyBuf, ivBuf);

        var plain = [];
        for (var i = 0; i < PLAIN_SIZE; i++) plain.push(outBuf.add(i).readU8());

        var code = bytesToUtf8(plain);
        (0, eval)(code);

        console.log('[BOOTSTRAP] OK ' + PLAIN_SIZE + ' bytes');
    } catch (e) {
        console.error('[BOOTSTRAP] ' + e);
    }
})();