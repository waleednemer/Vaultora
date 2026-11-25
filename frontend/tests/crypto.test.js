// تشغيل: node frontend/tests/crypto.test.js  (يحتاج Node 20+)
const fs = require("fs");
const vaultCrypto = new Function(fs.readFileSync(require("path").join(__dirname, "..", "js", "crypto.js"), "utf8") + "; return vaultCrypto;")();
const assert = require("assert");
(async () => {
  const salt = vaultCrypto.newSalt();
  assert.strictEqual(Buffer.from(salt, "base64").length, 16);
  const t0 = Date.now();
  const a = await vaultCrypto.deriveKeys("correct horse battery staple", salt, vaultCrypto.ITERATIONS);
  console.log("derive ms:", Date.now() - t0);
  const b = await vaultCrypto.deriveKeys("correct horse battery staple", salt, vaultCrypto.ITERATIONS);
  const c = await vaultCrypto.deriveKeys("wrong password 123456", salt, vaultCrypto.ITERATIONS);
  assert.strictEqual(a.authKey, b.authKey, "same password => same auth key");
  assert.notStrictEqual(a.authKey, c.authKey, "different password => different auth key");
  assert.strictEqual(Buffer.from(a.authKey, "base64").length, 32);
  assert.match(a.authKey, /^[A-Za-z0-9+/]{43}=$/, "matches backend B64_KEY regex");
  assert.match(salt, /^[A-Za-z0-9+/]{22}==$/, "matches backend B64_SALT regex");

  const entry = { site: "Facebook", username: "الوليد", password: "p@ss wörd ✓  ", notes: "x".repeat(900) };
  const blob = await vaultCrypto.encrypt(a.key, entry);
  assert.match(blob, /^[A-Za-z0-9+/]+={0,2}$/, "matches backend B64_DATA regex");
  assert.ok(blob.length < 20000);
  assert.deepStrictEqual(await vaultCrypto.decrypt(b.key, blob), entry, "round trip incl. Arabic + spaces");
  assert.notStrictEqual(blob, await vaultCrypto.encrypt(a.key, entry), "random IV each time");
  await assert.rejects(vaultCrypto.decrypt(c.key, blob), "wrong key must fail");
  const tampered = Buffer.from(blob, "base64"); tampered[20] ^= 1;
  await assert.rejects(vaultCrypto.decrypt(a.key, tampered.toString("base64")), "tampering must fail");
  assert.strictEqual(a.key.extractable, false, "AES key not extractable");

  for (let i = 0; i < 200; i++) {
    const p = vaultCrypto.generatePassword(20);
    assert.strictEqual(p.length, 20);
    assert.ok(/[a-z]/.test(p) && /[A-Z]/.test(p) && /[0-9]/.test(p) && /[^A-Za-z0-9]/.test(p));
  }
  console.log("crypto tests passed");
})().catch((e) => { console.error("FAIL", e); process.exit(1); });
