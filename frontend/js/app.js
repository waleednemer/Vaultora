"use strict";

const $ = (s) => document.querySelector(s);
const FIELDS = ["site", "url", "username", "email", "password", "notes"];
const MIN_MASTER = 12;
const AUTO_LOCK_MS = 5 * 60 * 1000;
const CLIPBOARD_CLEAR_MS = 20 * 1000;

let vaultInfo = { initialized: false };
let session = null; // { key } — مفتاح AES غير قابل للتصدير، في الذاكرة فقط
let entries = []; // عناصر مفكوكة التشفير: { id, updated_at, site, url, ... }
let editingId = null;
let revealed = new Set();
let lockTimer = null;
let clipTimer = null;
let toastTimer = null;

// ---------- مساعدات ----------
function setText(sel, msg) {
  const node = $(sel);
  node.textContent = msg;
  node.hidden = !msg;
}

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text) n.textContent = text;
  return n;
}

function button(label, onClick, cls) {
  const b = el("button", cls, label);
  b.type = "button";
  b.onclick = onClick;
  return b;
}

function show(screen) {
  $("#lock").hidden = screen !== "lock";
  $("#vault").hidden = screen !== "vault";
}

function safeUrl(u) {
  try {
    const x = new URL(u);
    return ["http:", "https:"].includes(x.protocol) ? x.href : null;
  } catch {
    return null;
  }
}

function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, 2800);
}

function connectionMessage(e) {
  return e instanceof TypeError ? "تعذر الاتصال بالخادم. تأكد من تشغيل الـ backend." : e.message;
}

// ---------- القفل التلقائي والحافظة ----------
function resetAutoLock() {
  clearTimeout(lockTimer);
  lockTimer = setTimeout(() => lock("تم قفل الخزنة تلقائيًا بسبب عدم النشاط."), AUTO_LOCK_MS);
}

for (const ev of ["pointerdown", "keydown"]) {
  addEventListener(ev, () => { if (session) resetAutoLock(); }, true);
}

function clearClipboard() {
  clearTimeout(clipTimer);
  clipTimer = null;
  navigator.clipboard.writeText("").catch(() => {});
}

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast(`تم النسخ. سيُمسح من الحافظة بعد ${CLIPBOARD_CLEAR_MS / 1000} ثانية.`);
    clearTimeout(clipTimer);
    clipTimer = setTimeout(clearClipboard, CLIPBOARD_CLEAR_MS);
  } catch {
    toast("تعذر النسخ. اسمح للمتصفح بالوصول إلى الحافظة.");
  }
}

// ---------- شاشة القفل ----------
function lockLabel() {
  return vaultInfo.initialized ? "فتح الخزنة" : "إنشاء الخزنة";
}

async function initLock(message = "") {
  show("lock");
  $("#lock-form").reset();
  setText("#lock-error", message);

  if (!window.crypto || !crypto.subtle) {
    setText("#lock-error", "هذا المتصفح لا يوفّر WebCrypto. افتح الموقع عبر localhost أو HTTPS.");
    $("#lock-submit").disabled = true;
    return;
  }
  try {
    vaultInfo = await api.vaultInfo();
  } catch (e) {
    setText("#lock-error", connectionMessage(e));
    return;
  }
  const isSetup = !vaultInfo.initialized;
  $("#confirm-row").hidden = !isSetup;
  $("#master2").required = isSetup;
  $("#setup-warn").hidden = !isSetup;
  $("#master").autocomplete = isSetup ? "new-password" : "current-password";
  $("#lock-hint").textContent = isSetup
    ? `أنشئ كلمة سر رئيسية لخزنتك (${MIN_MASTER} حرفًا على الأقل).`
    : "أدخل كلمة السر الرئيسية لفتح الخزنة.";
  $("#lock-submit").textContent = lockLabel();
  $("#lock-submit").disabled = false;
  $("#master").focus();
}

function lock(message = "") {
  clearTimeout(lockTimer);
  if (clipTimer) clearClipboard();
  session = null;
  entries = [];
  editingId = null;
  revealed.clear();
  api.setToken(null);
  if ($("#editor").open) $("#editor").close();
  $("#editor-form").reset();
  $("#search").value = "";
  $("#list").replaceChildren();
  setText("#error", "");
  initLock(message);
}

$("#lock-form").onsubmit = async (e) => {
  e.preventDefault();
  const submit = $("#lock-submit");
  const password = $("#master").value;
  const isSetup = !vaultInfo.initialized;
  setText("#lock-error", "");

  if (isSetup) {
    if (password.length < MIN_MASTER) {
      return setText("#lock-error", `كلمة السر الرئيسية قصيرة (الحد الأدنى ${MIN_MASTER} حرفًا).`);
    }
    if (password !== $("#master2").value) {
      return setText("#lock-error", "كلمتا السر غير متطابقتين.");
    }
  }

  submit.disabled = true;
  submit.textContent = "جارٍ التحقق…";
  try {
    const params = isSetup ? { salt: vaultCrypto.newSalt(), iterations: vaultCrypto.ITERATIONS } : vaultInfo;
    const { key, authKey } = await vaultCrypto.deriveKeys(password, params.salt, params.iterations);
    if (isSetup) {
      await api.setup({ salt: params.salt, iterations: params.iterations, auth_key: authKey });
      vaultInfo = { initialized: true, ...params };
    }
    const { token } = await api.login(authKey);
    api.setToken(token);
    session = { key };
    await loadEntries();
    $("#lock-form").reset();
    show("vault");
    render();
    resetAutoLock();
  } catch (err) {
    session = null;
    api.setToken(null);
    if (err.status === 409) return initLock("الخزنة موجودة مسبقًا. أدخل كلمة السر الرئيسية.");
    console.error(err);
    setText("#lock-error", connectionMessage(err));
  } finally {
    submit.disabled = false;
    submit.textContent = lockLabel();
  }
};

// ---------- الخزنة ----------
async function loadEntries() {
  const rows = await api.list();
  const out = [];
  let failed = 0;
  for (const r of rows) {
    try {
      out.push({ id: r.id, updated_at: r.updated_at, ...(await vaultCrypto.decrypt(session.key, r.data)) });
    } catch {
      failed++;
    }
  }
  entries = out;
  setText("#error", failed ? `تعذّر فك تشفير ${failed} عنصر (تالف أو من خزنة أخرى).` : "");
}

async function run(action, errSel = "#error") {
  try {
    setText(errSel, "");
    await action();
  } catch (e) {
    if (e.status === 401 && session) return lock("انتهت الجلسة. أدخل كلمة السر الرئيسية من جديد.");
    console.error(e);
    setText(errSel, connectionMessage(e));
  }
  if (session) render();
}

function card(entry) {
  const li = el("li", "entry");
  const info = el("div", "info");
  info.append(el("span", "site", entry.site));

  const who = [entry.username, entry.email].filter(Boolean).join(" · ");
  if (who) info.append(el("span", "meta", who));

  const href = entry.url && safeUrl(entry.url);
  if (href) {
    const a = el("a", "meta link", entry.url);
    a.href = href;
    a.target = "_blank";
    a.rel = "noopener noreferrer";
    info.append(a);
  }

  const shown = revealed.has(entry.id);
  info.append(el("span", "pw", shown ? entry.password : "••••••••••"));
  if (entry.notes) info.append(el("span", "notes", entry.notes));

  const actions = el("div", "actions");
  actions.append(
    button(shown ? "إخفاء" : "إظهار", () => {
      if (shown) revealed.delete(entry.id); else revealed.add(entry.id);
      render();
    }),
    button("نسخ", () => copy(entry.password)),
    button("تعديل", () => openEditor(entry)),
    button("حذف", () => removeEntry(entry), "del"),
  );
  li.append(info, actions);
  return li;
}

function render() {
  const q = $("#search").value.trim().toLowerCase();
  const items = entries.filter(
    (x) => !q || [x.site, x.username, x.email, x.url].some((v) => (v || "").toLowerCase().includes(q)),
  );
  $("#list").replaceChildren(...items.map(card));
  $("#empty").hidden = items.length > 0;
  $("#empty").textContent = entries.length ? "لا توجد نتائج مطابقة." : "الخزنة فارغة. أضف أول حساب من الزر أعلاه.";
  $("#count").textContent = `${entries.length} حساب محفوظ`;
}

function removeEntry(entry) {
  if (!confirm(`حذف حساب «${entry.site}» نهائيًا؟`)) return;
  run(async () => {
    await api.remove(entry.id);
    entries = entries.filter((x) => x.id !== entry.id);
    revealed.delete(entry.id);
  });
}

// ---------- نافذة الإضافة والتعديل ----------
function openEditor(entry) {
  const form = $("#editor-form");
  editingId = entry ? entry.id : null;
  $("#editor-title").textContent = entry ? "تعديل حساب" : "إضافة حساب";
  form.reset();
  for (const name of FIELDS) form.elements[name].value = entry ? entry[name] || "" : "";
  form.elements.password.type = "password";
  $("#toggle-pw").textContent = "إظهار";
  setText("#editor-error", "");
  $("#editor").showModal();
  form.elements.site.focus();
}

$("#add-btn").onclick = () => openEditor(null);
$("#cancel").onclick = () => $("#editor").close();
$("#lock-btn").onclick = () => lock();
$("#search").oninput = render;

$("#toggle-pw").onclick = () => {
  const input = $("#editor-form").elements.password;
  const hide = input.type === "text";
  input.type = hide ? "password" : "text";
  $("#toggle-pw").textContent = hide ? "إظهار" : "إخفاء";
};

$("#gen").onclick = () => {
  const input = $("#editor-form").elements.password;
  input.value = vaultCrypto.generatePassword(20);
  input.type = "text";
  $("#toggle-pw").textContent = "إخفاء";
};

$("#editor-form").onsubmit = (e) => {
  e.preventDefault();
  const form = e.target;
  const data = {};
  for (const name of FIELDS) {
    const v = form.elements[name].value;
    data[name] = name === "password" ? v : v.trim(); // لا نقصّ كلمة السر
  }
  if (data.url) {
    if (!/^[a-z][a-z0-9+.-]*:/i.test(data.url)) data.url = "https://" + data.url;
    if (!safeUrl(data.url)) return setText("#editor-error", "الرابط غير صالح.");
  }
  const id = editingId;
  run(async () => {
    const blob = await vaultCrypto.encrypt(session.key, data);
    const saved = id ? await api.update(id, blob) : await api.create(blob);
    const item = { id: saved.id, updated_at: saved.updated_at, ...data };
    entries = id ? entries.map((x) => (x.id === id ? item : x)) : [item, ...entries];
    $("#editor").close();
  }, "#editor-error");
};

initLock();
