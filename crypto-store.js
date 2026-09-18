const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

function requireSecret() {
  const s = String(process.env.A2B_SECRET || '').trim();
  if (!s || s === 'CAMBIAR_EN_EL_SERVIDOR' || s.length < 24) {
    throw new Error('A2B_SECRET no está configurado o es demasiado corto (mínimo 24 caracteres).');
  }
  return s;
}

function deriveKey(label = 'vault') {
  const secret = requireSecret();
  return crypto.createHash('sha256').update(`a2b:${label}:${secret}`, 'utf8').digest();
}

function timingSafeTextEqual(a, b) {
  const aa = Buffer.from(String(a || ''));
  const bb = Buffer.from(String(b || ''));
  if (aa.length !== bb.length) return false;
  return crypto.timingSafeEqual(aa, bb);
}

function deviceToken() {
  const secret = requireSecret();
  return crypto.createHmac('sha256', secret).update('a2b-device-v1').digest('hex');
}

function adminSessionToken() {
  const secret = requireSecret();
  return crypto.createHmac('sha256', secret).update('a2b-admin-session-v1').digest('hex');
}

function isAdminSecret(candidate) {
  try { return timingSafeTextEqual(candidate, requireSecret()); } catch { return false; }
}

function isDeviceToken(candidate) {
  try { return timingSafeTextEqual(candidate, deviceToken()); } catch { return false; }
}

function isAdminSessionToken(candidate) {
  try { return timingSafeTextEqual(candidate, adminSessionToken()); } catch { return false; }
}

function encryptObject(obj, label = 'vault') {
  const key = deriveKey(label);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const plain = Buffer.from(JSON.stringify(obj), 'utf8');
  const encrypted = Buffer.concat([cipher.update(plain), cipher.final()]);
  const tag = cipher.getAuthTag();
  return JSON.stringify({ v: 1, alg: 'AES-256-GCM', iv: iv.toString('base64'), tag: tag.toString('base64'), data: encrypted.toString('base64') });
}

function decryptObject(text, label = 'vault') {
  const p = JSON.parse(text);
  if (p.v !== 1 || p.alg !== 'AES-256-GCM') throw new Error('Formato cifrado no compatible.');
  const decipher = crypto.createDecipheriv('aes-256-gcm', deriveKey(label), Buffer.from(p.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(p.tag, 'base64'));
  const plain = Buffer.concat([decipher.update(Buffer.from(p.data, 'base64')), decipher.final()]);
  return JSON.parse(plain.toString('utf8'));
}

function atomicWrite(file, contents) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, contents, { mode: 0o600 });
  fs.renameSync(tmp, file);
}

function writeEncrypted(file, obj, label) {
  atomicWrite(file, encryptObject(obj, label));
}

function readEncrypted(file, label) {
  if (!fs.existsSync(file)) return null;
  return decryptObject(fs.readFileSync(file, 'utf8'), label);
}

module.exports = {
  requireSecret, deviceToken, adminSessionToken, isAdminSecret, isDeviceToken, isAdminSessionToken,
  encryptObject, decryptObject, writeEncrypted, readEncrypted, atomicWrite
};

