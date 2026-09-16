/*
 * BOOTSTRAP — Fastest Native AES Decryption
 * Uses pre-compiled libaes.so (no CModule compilation overhead)
 */

(function () {
    'use strict';

    var KEY_HEX = "__KEY_HEX__";
    var IV_HEX = "__IV_HEX__";
    var DATA_B64 = "__DATA_B64__";
    var PLAIN_SIZE = __PLAIN_SIZE__;

    function hexToBytes(hex) {
        var b = [];
        for (var i = 0; i < hex.length; i += 2) b.push(parseInt(hex.substr(i, 2), 16));
        return b;
    }

    function b64ToBytes(b64) {
        var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        var lookup = {};
        for (var i = 0; i < chars.length; i++) lookup[chars[i]] = i;
        var bytes = [], buf = 0, bits = 0;
        for (var j = 0; j < b64.length; j++) {
            var c = b64[j];
            if (c === '=') break;
            var v = lookup[c];
            if (v === undefined) continue;
            buf = (buf << 6) | v;
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                bytes.push((buf >> bits) & 0xFF);
            }
        }
        return bytes;
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
        // ═══════════════════════════════════════════════
        // LOAD libaes.so (no compilation — instant)
        // ═══════════════════════════════════════════════
        var libaes = null;
        try {
            libaes = Process.findModuleByName('libaes.so');
        } catch (e) {}
        if (!libaes) {
            libaes = Module.load('libaes.so');
        }

        var aes_decrypt = libaes.findExportByName('aes_decrypt');
        if (!aes_decrypt) {
            throw new Error('aes_decrypt not found in libaes.so');
        }

        var decryptFn = new NativeFunction(
            aes_decrypt, 'void',
            ['pointer', 'pointer', 'uint32', 'pointer', 'pointer']
        );

        // ═══════════════════════════════════════════════
        // PREPARE BUFFERS
        // ═══════════════════════════════════════════════
        var encBytes = b64ToBytes(DATA_B64);
        var keyBytes = hexToBytes(KEY_HEX);
        var ivBytes  = hexToBytes(IV_HEX);

        var inBuf  = Memory.alloc(encBytes.length);
        var outBuf = Memory.alloc(encBytes.length);
        var keyBuf = Memory.alloc(32);
        var ivBuf  = Memory.alloc(16);

        for (var i = 0; i < encBytes.length; i++) inBuf.add(i).writeU8(encBytes[i]);
        for (var i = 0; i < 32; i++) keyBuf.add(i).writeU8(keyBytes[i]);
        for (var i = 0; i < 16; i++) ivBuf.add(i).writeU8(ivBytes[i]);

        // ═══════════════════════════════════════════════
        // DECRYPT (native, ~5ms for 676KB)
        // ═══════════════════════════════════════════════
        decryptFn(outBuf, inBuf, encBytes.length, keyBuf, ivBuf);

        // ═══════════════════════════════════════════════
        // EXECUTE
        // ═══════════════════════════════════════════════
        var plain = [];
        for (var i = 0; i < PLAIN_SIZE; i++) plain.push(outBuf.add(i).readU8());

        var code = bytesToUtf8(plain);
        (0, eval)(code);
    } catch (e) {
        console.error('[BOOTSTRAP] ' + e);
    }
})();