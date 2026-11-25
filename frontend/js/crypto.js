// كل التشفير يتم هنا في المتصفح عبر WebCrypto. السيرفر لا يرى كلمة السر الرئيسية ولا مفتاح التشفير.
//
// كلمة السر الرئيسية --PBKDF2-SHA256 (600k)--> مفتاح رئيسي (256 bit)
//   --HKDF "vault-enc"-->  مفتاح AES-GCM (غير قابل للتصدير، يبقى في الذاكرة فقط)
//   --HKDF "vault-auth"--> مفتاح الدخول (يُرسل للسيرفر، الذي يخزّن hash له فقط)
const vaultCrypto = (() => {
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const ITERATIONS = 600000;

  function toB64(buf) {
    const bytes = new Uint8Array(buf);
    let s = "";
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }
  const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

  const newSalt = () => toB64(crypto.getRandomValues(new Uint8Array(16)));

  async function deriveKeys(password, saltB64, iterations) {
    const salt = fromB64(saltB64);
    const base = await crypto.subtle.importKey("raw", enc.encode(password.normalize("NFKC")), "PBKDF2", false, ["deriveBits"]);
    const master = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, base, 256);
    const hkdf = await crypto.subtle.importKey("raw", master, "HKDF", false, ["deriveBits", "deriveKey"]);
    const params = (info) => ({ name: "HKDF", hash: "SHA-256", salt, info: enc.encode(info) });
    const key = await crypto.subtle.deriveKey(params("vault-enc"), hkdf, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    const authKey = toB64(await crypto.subtle.deriveBits(params("vault-auth"), hkdf, 256));
    return { key, authKey };
  }

  // الناتج: base64( iv[12] + ciphertext+tag )
  async function encrypt(key, obj) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(JSON.stringify(obj))));
    const out = new Uint8Array(iv.length + ct.length);
    out.set(iv);
    out.set(ct, iv.length);
    return toB64(out);
  }

  async function decrypt(key, blob) {
    const raw = fromB64(blob);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: raw.slice(0, 12) }, key, raw.slice(12));
    return JSON.parse(dec.decode(pt));
  }

  // عدد عشوائي منتظم بلا انحياز (rejection sampling)
  function randomInt(max) {
    const limit = Math.floor(0x100000000 / max) * max;
    const buf = new Uint32Array(1);
    do {
      crypto.getRandomValues(buf);
    } while (buf[0] >= limit);
    return buf[0] % max;
  }

  function generatePassword(length = 20) {
    const sets = ["abcdefghijkmnopqrstuvwxyz", "ABCDEFGHJKLMNPQRSTUVWXYZ", "23456789", "!@#$%^&*()-_=+[]{};:,.?"];
    const all = sets.join("");
    const pick = (chars) => chars[randomInt(chars.length)];
    const out = sets.map(pick); // حرف واحد على الأقل من كل مجموعة
    while (out.length < length) out.push(pick(all));
    for (let i = out.length - 1; i > 0; i--) {
      const j = randomInt(i + 1);
      [out[i], out[j]] = [out[j], out[i]];
    }
    return out.join("");
  }

  return { ITERATIONS, newSalt, deriveKeys, encrypt, decrypt, generatePassword };
})();
