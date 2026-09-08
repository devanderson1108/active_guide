// 零依赖：使用 Node 内置 crypto 模块，无需 npm install crypto-js
import crypto from "node:crypto";

// Base64url 字符集（64 个字符，URL 安全，无需转义）
const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const IDX = Object.fromEntries([...ALPHABET].map((c, i) => [c, i]));
const BASE = 64;
const OFFSET = 17;

// ==================== 1. 基础工具函数 ====================

/** 单字符在 Base64url 字符集上做移位（环绕） */
function shiftChar(c, shift) {
    return ALPHABET[(IDX[c] + shift + BASE) % BASE];
}

/**
 * 从任意长度的密码派生出固定 32 字节（256 位）的 AES 密钥。
 * 用 SHA-256 归一化，兼容任意长度密码。
 * @param {string} secretKey - 任意长度的密码
 * @returns {Buffer} 32 字节 AES-256 密钥
 */
function deriveKey(secretKey) {
    return crypto.createHash("sha256").update(secretKey, "utf8").digest();
}

/** 伪装：字符移位 + 奇偶位置交错打乱 */
function disguise(str) {
    const shifted = [...str].map(c => shiftChar(c, OFFSET));
    const evens = [];
    const odds = [];
    for (let i = 0; i < shifted.length; i++) {
        (i % 2 === 0 ? evens : odds).push(shifted[i]);
    }
    return evens.join("") + odds.join("");
}

/** 还原伪装：解交错 + 逆移位 */
function undisguise(str) {
    const len = str.length;
    const evenCount = Math.ceil(len / 2);
    let evenIndex = 0;
    let oddIndex = evenCount;
    const out = new Array(len);
    for (let i = 0; i < len; i++) {
        const c = i % 2 === 0 ? str[evenIndex++] : str[oddIndex++];
        out[i] = shiftChar(c, BASE - OFFSET);
    }
    return out.join("");
}


// ==================== 2. 加密并伪装 ====================

/**
 * AES-256-CTR 加密 -> 打包(IV+密文) -> Base64url 编码 -> 移位打乱伪装
 * @param {string} plainText - 待加密的明文
 * @param {string} secretKey - 密钥（任意长度）
 * @returns {string} 伪装后的紧凑字符串
 */
export function encryptAndDisguise(plainText, secretKey) {
    const key = deriveKey(secretKey);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv("aes-256-ctr", key, iv);
    const enc = Buffer.concat([cipher.update(plainText, "utf8"), cipher.final()]);

    // 打包：[16字节 IV][密文]，Base64url 紧凑编码
    const packed = Buffer.concat([iv, enc]);
    return disguise(packed.toString("base64url"));
}


// ==================== 3. 还原并解密 ====================

/**
 * 还原伪装 -> Base64url 解码 -> 拆出 IV/密文 -> AES-256-CTR 解密
 * @param {string} disguisedStr - 伪装字符串
 * @param {string} secretKey - 密钥（需与加密时一致）
 * @returns {string} 解密后的明文
 */
export function undisguiseAndDecrypt(disguisedStr, secretKey) {
    const packed = Buffer.from(undisguise(disguisedStr), "base64url");
    const iv = packed.subarray(0, 16);
    const enc = packed.subarray(16);

    const key = deriveKey(secretKey);
    const decipher = crypto.createDecipheriv("aes-256-ctr", key, iv);
    return Buffer.concat([decipher.update(enc), decipher.final()]).toString("utf8");
}