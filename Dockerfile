# syntax=docker/dockerfile:1
FROM mcr.microsoft.com/playwright:v1.55.0-noble
WORKDIR /app
RUN mkdir -p /app && cat > /app/package.json <<'A2BPKG'
{
  "name": "a2b-by-vex-bridge",
  "version": "0.4.0",
  "private": true,
  "description": "Secure A2B by VEX bridge for Aspel ADM and CFDI delivery",
  "type": "commonjs",
  "scripts": {
    "start": "node server.js",
    "check": "node --check server.js && node --check lib/crypto-store.js && node --check lib/aspel.js"
  },
  "dependencies": {
    "playwright": "1.55.0"
  },
  "engines": {
    "node": ">=20"
  }
}

A2BPKG
RUN mkdir -p /app/lib && cat > /app/lib/crypto-store.js <<'A2BCRYPTO'
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

function isAdminSecret(candidate) {
  try { return timingSafeTextEqual(candidate, requireSecret()); } catch { return false; }
}

function isDeviceToken(candidate) {
  try { return timingSafeTextEqual(candidate, deviceToken()); } catch { return false; }
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
  requireSecret, deviceToken, isAdminSecret, isDeviceToken,
  encryptObject, decryptObject, writeEncrypted, readEncrypted, atomicWrite
};

A2BCRYPTO
RUN mkdir -p /app/lib && cat > /app/lib/aspel.js <<'A2BASPEL'
const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');
const { writeEncrypted, readEncrypted } = require('./crypto-store');

function files(dataDir) {
  return {
    creds: path.join(dataDir, 'aspel-credentials.enc'),
    session: path.join(dataDir, 'aspel-session.enc'),
    screenshot: path.join(dataDir, 'aspel-login-test.png')
  };
}

function saveCredentials(dataDir, creds) {
  const clean = {
    rfc: String(creds.rfc || '').trim().toUpperCase(),
    user: String(creds.user || '').trim(),
    password: String(creds.password || '')
  };
  if (!clean.rfc || !clean.user || !clean.password) throw new Error('Faltan RFC, usuario o contraseña de Aspel.');
  writeEncrypted(files(dataDir).creds, clean, 'aspel-credentials');
  return { rfc: clean.rfc, userMasked: mask(clean.user) };
}

function getCredentials(dataDir) {
  return readEncrypted(files(dataDir).creds, 'aspel-credentials');
}

function credentialStatus(dataDir) {
  const c = getCredentials(dataDir);
  return c ? { configured: true, rfc: c.rfc || '', userMasked: mask(c.user) } : { configured: false };
}

function mask(s) {
  s = String(s || '');
  if (s.length <= 2) return '••';
  return s.slice(0, 1) + '•'.repeat(Math.min(8, s.length - 2)) + s.slice(-1);
}

async function firstVisible(page, selectors) {
  for (const sel of selectors) {
    const loc = page.locator(sel).first();
    try { if (await loc.count() && await loc.isVisible({ timeout: 700 })) return loc; } catch {}
  }
  return null;
}

async function semanticField(page, kind) {
  const patterns = {
    rfc: /rfc|registro federal/i,
    user: /usuario|user|correo|email/i,
    pass: /contrase(?:ñ|n)a|password|clave/i
  };
  try {
    const byLabel = page.getByLabel(patterns[kind]).first();
    if (await byLabel.count() && await byLabel.isVisible({ timeout: 500 })) return byLabel;
  } catch {}
  try {
    const byPlaceholder = page.getByPlaceholder(patterns[kind]).first();
    if (await byPlaceholder.count() && await byPlaceholder.isVisible({ timeout: 500 })) return byPlaceholder;
  } catch {}
  return null;
}

async function detectLoginFields(page) {
  let rfc = await semanticField(page, 'rfc');
  let user = await semanticField(page, 'user');
  let pass = await semanticField(page, 'pass');

  if (!rfc) rfc = await firstVisible(page, [
    'input[name*="rfc" i]', 'input[id*="rfc" i]', 'input[placeholder*="rfc" i]'
  ]);
  if (!user) user = await firstVisible(page, [
    'input[name*="usuario" i]', 'input[id*="usuario" i]', 'input[placeholder*="usuario" i]',
    'input[name*="user" i]', 'input[id*="user" i]', 'input[type="email"]'
  ]);
  if (!pass) pass = await firstVisible(page, ['input[type="password"]']);

  // Fallback específico para el login actual de ADM: RFC, Usuario, Contraseña.
  const visibleText = page.locator('input:not([type="hidden"]):not([type="password"]):not([type="submit"]):not([type="button"])');
  const count = await visibleText.count().catch(() => 0);
  const visible = [];
  for (let i = 0; i < count; i++) {
    const loc = visibleText.nth(i);
    try { if (await loc.isVisible({ timeout: 150 })) visible.push(loc); } catch {}
  }
  if (!rfc && visible.length >= 1) rfc = visible[0];
  if (!user && visible.length >= 2) user = visible[1];
  return { rfc, user, pass };
}

async function testLogin(dataDir, admUrl) {
  const creds = getCredentials(dataDir);
  if (!creds) throw new Error('Primero guarda las credenciales de Aspel en /setup.');
  if (!creds.rfc || !creds.user || !creds.password) throw new Error('Las credenciales guardadas deben incluir RFC, usuario y contraseña.');
  let browser = null;
  let context = null;
  const result = { ok: false, url: '', note: '' };
  try {
    browser = await chromium.launch({
      headless: true,
      chromiumSandbox: false,
      args: [
        '--no-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--disable-software-rasterizer',
        '--disable-extensions',
        '--disable-background-networking',
        '--disable-component-update',
        '--disable-default-apps',
        '--disable-sync',
        '--disable-translate',
        '--mute-audio',
        '--no-first-run',
        '--no-zygote',
        '--renderer-process-limit=1',
        '--disable-features=IsolateOrigins,site-per-process',
        '--js-flags=--max-old-space-size=128'
      ]
    });
    context = await browser.newContext({ viewport: { width: 900, height: 650 } });
    const page = await context.newPage();
    await page.route('**/*', route => {
      const t = route.request().resourceType();
      if (['image','media','font'].includes(t)) return route.abort();
      return route.continue();
    });
    await page.goto(admUrl, { waitUntil: 'domcontentloaded', timeout: 45000 });
    const { rfc, user, pass } = await detectLoginFields(page);
    if (!rfc || !user || !pass) {
      result.note = `No pude identificar los tres campos de Aspel (RFC:${!!rfc}, usuario:${!!user}, contraseña:${!!pass}).`;
      await page.screenshot({ path: files(dataDir).screenshot, fullPage: false }).catch(() => {});
      return result;
    }

    await rfc.fill(creds.rfc);
    await user.fill(creds.user);
    await pass.fill(creds.password);

    let submit = null;
    try {
      const semanticSubmit = page.getByRole('button', { name: /iniciar sesi[oó]n|ingresar|entrar|iniciar/i }).first();
      if (await semanticSubmit.count() && await semanticSubmit.isVisible({ timeout: 500 })) submit = semanticSubmit;
    } catch {}
    if (!submit) submit = await firstVisible(page, [
      'button[type="submit"]', 'input[type="submit"]',
      'button:has-text("Iniciar sesión")', 'button:has-text("Ingresar")', 'button:has-text("Entrar")', 'button:has-text("Iniciar")'
    ]);

    const beforeUrl = page.url();
    if (submit) await submit.click(); else await pass.press('Enter');
    await page.waitForTimeout(5000);
    await page.waitForLoadState('networkidle', { timeout: 15000 }).catch(() => {});

    result.url = page.url();
    const passwordStillVisible = await page.locator('input[type="password"]').first().isVisible().catch(() => false);
    const loginButtonStillVisible = await page.getByRole('button', { name: /iniciar sesi[oó]n/i }).first().isVisible().catch(() => false);
    const movedAway = result.url !== beforeUrl && !/login\.html|\/login\/?$/i.test(result.url);
    result.ok = movedAway || (!passwordStillVisible && !loginButtonStillVisible);
    result.note = result.ok
      ? `Sesión iniciada correctamente en Aspel. URL final: ${result.url}`
      : `Aspel mantuvo la pantalla de acceso después de enviar RFC + usuario + contraseña. URL: ${result.url}`;

    if (result.ok) {
      const state = await context.storageState();
      writeEncrypted(files(dataDir).session, state, 'aspel-session');
    } else {
      await page.screenshot({ path: files(dataDir).screenshot, fullPage: false }).catch(() => {});
    }
    return result;
  } catch (e) {
    const msg = String(e && e.message || e);
    if (/browser.*closed|target.*closed|crash|ENOMEM|out of memory|killed/i.test(msg)) {
      throw new Error('BROWSER_RESOURCE_ERROR: Chromium se cerró durante la prueba. En Render Free suele indicar falta de RAM.');
    }
    throw e;
  } finally {
    if (context) await context.close().catch(() => {});
    if (browser) await browser.close().catch(() => {});
  }
}

async function pingAspel(admUrl) {
  const started = Date.now();
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 12000);
    const r = await fetch(admUrl, { redirect: 'follow', signal: controller.signal, headers: { 'User-Agent': 'A2B-by-VEX/0.4' } });
    clearTimeout(timer);
    return { ok: r.status >= 200 && r.status < 500, status: r.status, finalUrl: r.url, ms: Date.now() - started };
  } catch (e) {
    return { ok: false, status: 0, finalUrl: admUrl, ms: Date.now() - started, error: String(e && e.message || e) };
  }
}

async function issueInvoice(_dataDir, packet) {
  // La autenticación y la cola ya están resueltas. El flujo de timbrado necesita
  // calibrarse contra la cuenta real de Aspel ADM porque los selectores/campos
  // del portal no están documentados como API pública estable.
  return {
    status: 'PENDING_ASPEL_CALIBRATION',
    note: 'Paquete fiscal recibido y resguardado. Falta calibrar el llenado/timbrado real en Aspel ADM.',
    invoice: packet.invoice
  };
}

module.exports = { saveCredentials, credentialStatus, testLogin, pingAspel, issueInvoice };

A2BASPEL
RUN mkdir -p /app && cat > /app/server.js <<'A2BSERVER'
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');
const { requireSecret, deviceToken, isAdminSecret, isDeviceToken, atomicWrite } = require('./lib/crypto-store');
const aspel = require('./lib/aspel');

const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const PUBLIC_DIR = path.join(__dirname, 'public');
const ASPEL_ADM_URL = process.env.ASPEL_ADM_URL || 'https://adm.aspel.com.mx/login.html';
const invoicesFile = path.join(DATA_DIR, 'invoices.json');
fs.mkdirSync(DATA_DIR, { recursive: true });

function secretReady() { try { requireSecret(); return true; } catch { return false; } }
function loadInvoices() { try { return JSON.parse(fs.readFileSync(invoicesFile, 'utf8')); } catch { return {}; } }
function saveInvoices(x) { atomicWrite(invoicesFile, JSON.stringify(x, null, 2)); }
function json(res, status, obj) { const body = JSON.stringify(obj); res.writeHead(status, cors({ 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(body) })); res.end(body); }
function text(res, status, body, type='text/plain; charset=utf-8') { res.writeHead(status, cors({ 'Content-Type': type })); res.end(body); }
function cors(headers={}) { return { 'Access-Control-Allow-Origin':'*', 'Access-Control-Allow-Headers':'Content-Type, Authorization, X-A2B-Admin', 'Access-Control-Allow-Methods':'GET,POST,OPTIONS', 'Cache-Control':'no-store', ...headers }; }
function bearer(req) { const m=String(req.headers.authorization||'').match(/^Bearer\s+(.+)$/i); return m?m[1]:''; }
function admin(req) { return secretReady() && isAdminSecret(req.headers['x-a2b-admin']); }
function device(req) { return secretReady() && isDeviceToken(bearer(req)); }
function safeId(s) { return String(s||'').replace(/[^A-Za-z0-9._-]/g,'_').slice(0,120); }
function readBody(req, max=25*1024*1024) { return new Promise((resolve,reject)=>{let size=0,chunks=[];req.on('data',c=>{size+=c.length;if(size>max){reject(new Error('BODY_TOO_LARGE'));req.destroy();return}chunks.push(c)});req.on('end',()=>{const raw=Buffer.concat(chunks).toString('utf8');try{resolve(raw?JSON.parse(raw):{})}catch{reject(new Error('JSON_INVALID'))}});req.on('error',reject)}); }
function b64Data(s) { if(!s)return null; const m=String(s).match(/^data:[^;]+;base64,(.*)$/s); return Buffer.from(m?m[1]:String(s),'base64'); }
function fileB64(file) { return fs.existsSync(file)?fs.readFileSync(file).toString('base64'):''; }
function invoicePublic(inv, includeFiles=false){const out={bridgeId:inv.bridgeId,invoice:inv.invoice,status:inv.status,note:inv.note||'',uuid:inv.uuid||'',folio:inv.folio||'',updatedAt:inv.updatedAt};if(includeFiles&&inv.status==='TIMBRADA'){out.pdfBase64=fileB64(inv.pdfPath);out.xmlBase64=fileB64(inv.xmlPath)}return out}

function serveSetup(res){const f=path.join(PUBLIC_DIR,'setup.html');text(res,200,fs.readFileSync(f,'utf8'),'text/html; charset=utf-8')}
function serveApp(res){const f=path.join(PUBLIC_DIR,'index.html');text(res,200,fs.readFileSync(f,'utf8'),'text/html; charset=utf-8')}

async function handler(req,res){
  if(req.method==='OPTIONS'){res.writeHead(204,cors());return res.end()}
  const u=new URL(req.url,`http://${req.headers.host||'localhost'}`), p=u.pathname;
  if(req.method==='GET'&&(p==='/'||p==='/app'||p==='/app/'))return serveApp(res);
  if(req.method==='GET'&&p==='/setup')return serveSetup(res);
  if(req.method==='GET'&&p==='/api/health')return json(res,200,{ok:true,service:'A2B by VEX Aspel Bridge',version:'0.4.0',secureConfigured:secretReady()});

  if(p.startsWith('/api/admin/')){
    if(!admin(req))return json(res,401,{error:'ADMIN_UNAUTHORIZED'});
    if(req.method==='GET'&&p==='/api/admin/status')return json(res,200,{ok:true,deviceToken:deviceToken(),aspel:aspel.credentialStatus(DATA_DIR),aspelAdmUrl:ASPEL_ADM_URL,invoices:Object.values(loadInvoices()).map(x=>invoicePublic(x,false)).reverse()});
    if(req.method==='POST'&&p==='/api/admin/aspel/credentials'){
      try{const b=await readBody(req);return json(res,200,{ok:true,...aspel.saveCredentials(DATA_DIR,b)})}catch(e){return json(res,400,{error:e.message})}
    }
    if(req.method==='GET'&&p==='/api/admin/runtime'){
      const m=process.memoryUsage();
      return json(res,200,{ok:true,version:'0.4.0',memoryMB:{rss:Math.round(m.rss/1048576),heapUsed:Math.round(m.heapUsed/1048576),external:Math.round(m.external/1048576)}});
    }
    if(req.method==='POST'&&p==='/api/admin/aspel/ping'){
      return json(res,200,{ok:true,result:await aspel.pingAspel(ASPEL_ADM_URL)});
    }
    if(req.method==='POST'&&p==='/api/admin/aspel/test-login'){
      try{return json(res,200,{ok:true,result:await aspel.testLogin(DATA_DIR,ASPEL_ADM_URL)})}catch(e){console.error('ASPEL_TEST_LOGIN_ERROR',e);return json(res,500,{error:e.message})}
    }
    const m=p.match(/^\/api\/admin\/invoices\/([^/]+)\/complete$/);
    if(req.method==='POST'&&m){
      try{
        const b=await readBody(req), all=loadInvoices(), id=safeId(m[1]), inv=all[id]; if(!inv)return json(res,404,{error:'INVOICE_NOT_FOUND'});
        const dir=path.join(DATA_DIR,'cfdi');fs.mkdirSync(dir,{recursive:true});
        if(b.pdfBase64){inv.pdfPath=path.join(dir,`${id}.pdf`);atomicWrite(inv.pdfPath,b64Data(b.pdfBase64));}
        if(b.xmlBase64){inv.xmlPath=path.join(dir,`${id}.xml`);atomicWrite(inv.xmlPath,b64Data(b.xmlBase64));}
        inv.uuid=String(b.uuid||inv.uuid||'');inv.folio=String(b.folio||inv.folio||'');
        if(inv.pdfPath&&inv.xmlPath)inv.status='TIMBRADA';else inv.status='CFDI_INCOMPLETO';
        inv.updatedAt=new Date().toISOString();all[id]=inv;saveInvoices(all);return json(res,200,{ok:true,...invoicePublic(inv,true)});
      }catch(e){return json(res,400,{error:e.message})}
    }
    return json(res,404,{error:'ADMIN_ROUTE_NOT_FOUND'});
  }

  if(p.startsWith('/api/invoices')){
    if(!device(req))return json(res,401,{error:'DEVICE_UNAUTHORIZED'});
    if(req.method==='POST'&&p==='/api/invoices'){
      try{
        const packet=await readBody(req);if(!packet.invoice)return json(res,400,{error:'MISSING_INVOICE_ID'});
        const all=loadInvoices(), id=safeId(packet.invoice);let inv=all[id];
        if(inv){return json(res,200,invoicePublic(inv,true));}
        inv={bridgeId:id,invoice:packet.invoice,status:'RECEIVED',packet,createdAt:new Date().toISOString(),updatedAt:new Date().toISOString()};
        const result=await aspel.issueInvoice(DATA_DIR,packet);Object.assign(inv,result,{bridgeId:id,updatedAt:new Date().toISOString()});all[id]=inv;saveInvoices(all);
        return json(res,202,invoicePublic(inv,true));
      }catch(e){return json(res,400,{error:e.message})}
    }
    const m=p.match(/^\/api\/invoices\/([^/]+)$/);
    if(req.method==='GET'&&m){const all=loadInvoices(),inv=all[safeId(m[1])];return inv?json(res,200,invoicePublic(inv,true)):json(res,404,{error:'INVOICE_NOT_FOUND'});}
  }
  return json(res,404,{error:'NOT_FOUND'});
}

const server=http.createServer((req,res)=>Promise.resolve(handler(req,res)).catch(e=>{console.error(e);json(res,500,{error:'INTERNAL_ERROR'})}));
server.listen(PORT,'0.0.0.0',()=>{
  console.log(`A2B Bridge escuchando en :${PORT}`);
  console.log(secretReady()?'Seguridad: A2B_SECRET configurado.':'ATENCIÓN: configura A2B_SECRET antes de usar credenciales o facturación.');
});

A2BSERVER
RUN mkdir -p /app/public && cat > /app/public/index.html <<'A2BAPPV04_7F2A'
<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#b41016">
<link rel="manifest" href="manifest.webmanifest">
<link rel="icon" href="icon-192.png">
<link rel="apple-touch-icon" href="icon-192.png">
<title>A2B by VEX · Operación en campo</title>
<style>
:root{--bg:#f3f4f6;--card:#fff;--ink:#17202a;--muted:#6b7280;--line:#e5e7eb;--red:#c8161d;--red2:#991218;--green:#087f5b;--amber:#a16207;--nav:#111827;--soft:#fff7f7;--blue:#1d4ed8}
*{box-sizing:border-box}html{background:var(--bg)}body{margin:0;background:var(--bg);color:var(--ink);font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;padding-bottom:88px}.top{position:sticky;top:0;z-index:20;background:linear-gradient(135deg,#981218,#d61b23);color:#fff;padding:13px 15px 12px;box-shadow:0 4px 16px #0002}.brand{display:flex;align-items:center;gap:10px;max-width:780px;margin:auto}.logo{background:#fff;color:var(--red);font-weight:950;border-radius:11px;padding:7px 10px;letter-spacing:1px}.top h1{font-size:17px;margin:0}.top small{color:#ffe4e6}.wrap{max-width:780px;margin:auto;padding:13px}.hero{background:linear-gradient(135deg,#fff,#fff6f6);border:1px solid #f1d1d4;border-radius:18px;padding:15px;margin-bottom:11px}.hero h2{margin:0 0 4px;font-size:20px}.hero p{margin:0;color:var(--muted);font-size:13px;line-height:1.45}.nextfolio{display:inline-block;margin-top:8px;padding:5px 8px;border-radius:999px;background:#fff0f1;color:var(--red2);font-size:11px;font-weight:800}.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:9px}.kpi{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:12px}.kpi span{display:block;color:var(--muted);font-size:11px}.kpi b{font-size:21px}.actions{display:grid;grid-template-columns:repeat(2,1fr);gap:9px;margin:11px 0}.action{border:1px solid var(--line);border-radius:16px;padding:15px 12px;text-align:left;background:#fff;font-weight:850;color:var(--ink);box-shadow:0 1px 0 #0001}.action.primary{background:var(--red);color:#fff;border-color:var(--red)}.action small{display:block;font-weight:500;opacity:.7;margin-top:4px}.view{display:none}.view.active{display:block}.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:13px;margin:9px 0}.card h3{margin:0 0 9px;font-size:16px}.subtle{color:var(--muted);font-size:12px;line-height:1.4}.list{display:flex;flex-direction:column;gap:8px}.item{display:flex;justify-content:space-between;gap:9px;align-items:flex-start;border:1px solid var(--line);border-radius:13px;padding:11px;background:#fff}.item .main{min-width:0;flex:1}.item b{display:block}.item small{display:block;color:var(--muted);margin-top:3px;line-height:1.35}.badge{font-size:10px;font-weight:800;padding:5px 7px;border-radius:999px;background:#fff7ed;color:var(--amber);border:1px solid #fed7aa;white-space:nowrap}.badge.good{background:#ecfdf5;color:#047857;border-color:#a7f3d0}.badge.red{background:#fff1f2;color:#be123c;border-color:#fecdd3}.btn{border:1px solid var(--line);background:#fff;color:var(--ink);border-radius:11px;padding:10px 12px;font-weight:760}.btn.primary{background:var(--red);border-color:var(--red);color:#fff}.btn.green{background:var(--green);border-color:var(--green);color:#fff}.btn.blue{background:var(--blue);border-color:var(--blue);color:#fff}.btn.block{width:100%;padding:13px}.btn.small{padding:7px 9px;font-size:12px}.toolbar{display:flex;gap:7px;flex-wrap:wrap;margin:8px 0 11px}.empty{text-align:center;color:var(--muted);padding:20px 10px}.field{margin:9px 0}.field label{display:block;font-size:12px;font-weight:760;margin-bottom:5px;color:#374151}.field input,.field select,.field textarea{width:100%;border:1px solid #d1d5db;border-radius:11px;padding:12px;font:inherit;background:#fff;color:var(--ink)}.field textarea{min-height:70px;resize:vertical}.row{display:grid;grid-template-columns:1fr 1fr;gap:9px}.check{display:flex;gap:8px;align-items:flex-start;margin:9px 0;font-size:13px}.tax{background:#f8fafc;border:1px solid var(--line);border-radius:13px;padding:10px}.taxline{display:flex;justify-content:space-between;gap:8px;padding:6px 0;border-bottom:1px dashed #d1d5db}.taxline:last-child{border:0}.taxline.total{font-size:18px;font-weight:900;color:var(--red)}.nav{position:fixed;left:0;right:0;bottom:0;z-index:30;background:#fff;border-top:1px solid var(--line);display:grid;grid-template-columns:repeat(5,1fr);padding-bottom:max(6px,env(safe-area-inset-bottom));box-shadow:0 -5px 20px #0001}.nav button{border:0;background:transparent;padding:9px 2px 6px;color:#6b7280;font-size:10px}.nav button b{display:block;font-size:18px;line-height:20px}.nav button.active{color:var(--red)}dialog{border:0;border-radius:18px;padding:0;max-width:min(94vw,640px);width:100%;box-shadow:0 18px 60px #0005}dialog::backdrop{background:#0008}.modal{padding:15px;max-height:88vh;overflow:auto}.modalhead{display:flex;justify-content:space-between;align-items:center;position:sticky;top:-15px;background:#fff;padding:10px 0;z-index:2}.modalhead h2{font-size:18px;margin:0}.close{border:0;background:#eef0f2;border-radius:999px;width:34px;height:34px;font-size:18px}.notice{font-size:12px;padding:10px;border-radius:10px;background:#fff7ed;color:#7c2d12;border:1px solid #fed7aa;margin:9px 0;line-height:1.4}.success{background:#ecfdf5;color:#065f46;border-color:#a7f3d0}.code{white-space:pre-wrap;word-break:break-word;background:#111827;color:#d1fae5;border-radius:12px;padding:10px;font-size:11px;max-height:240px;overflow:auto}.hint{color:var(--muted);font-size:11px}.danger{color:#b91c1c}.doc-actions{display:grid;grid-template-columns:repeat(2,1fr);gap:8px;margin-top:10px}.doc-actions .btn:first-child{grid-column:1/-1}.divider{height:1px;background:var(--line);margin:12px 0}.mini{font-size:11px}.right{text-align:right}.pillbar{display:flex;gap:6px;overflow:auto;padding-bottom:3px}.pill{white-space:nowrap;border:1px solid var(--line);background:#fff;border-radius:999px;padding:7px 10px;font-size:12px;font-weight:700}
@media(min-width:700px){.grid{grid-template-columns:repeat(4,1fr)}.actions{grid-template-columns:repeat(4,1fr)}.nav{max-width:780px;left:50%;transform:translateX(-50%);border-left:1px solid var(--line);border-right:1px solid var(--line)}}
@media print{body>*{display:none!important}#printArea{display:block!important;position:absolute;inset:0;background:#fff;color:#111;padding:16mm 17mm;font-family:Arial,sans-serif}.doc{min-height:250mm}.docHead{display:flex;justify-content:space-between;align-items:flex-start;border-bottom:3px solid #b41016;padding-bottom:10px;margin-bottom:18px}.docBrand{font-size:34px;font-weight:900;color:#b41016}.docMeta{text-align:right;font-size:12px;line-height:1.55}.doc h1{font-size:22px;margin:10px 0 5px}.doc h2{font-size:15px;margin:0 0 18px;color:#555}.doc p{font-size:13px;line-height:1.6}.doc table{width:100%;border-collapse:collapse;margin-top:16px;font-size:12px}.doc th,.doc td{border-bottom:1px solid #ddd;padding:8px 6px;text-align:left}.doc th{background:#f4f4f4}.doc .totals{width:55%;margin-left:auto;margin-top:18px}.doc .totals div{display:flex;justify-content:space-between;padding:5px 0}.doc .grand{font-size:17px;font-weight:900;border-top:2px solid #b41016;margin-top:4px;padding-top:8px}.doc .sig{margin-top:55px;text-align:center}.doc .sig:before{content:'';display:block;width:250px;border-top:1px solid #000;margin:0 auto 8px}.certDoc{border:3px solid #b41016;padding:17mm 13mm;min-height:245mm}.certDoc .docBrand{text-align:center}.certDoc h1{text-align:center;margin-top:8px}.certDoc h2{text-align:center}.certDoc .folio{text-align:right;font-weight:bold}.certDoc p{font-size:14px;line-height:1.55}.certGrid{display:grid;grid-template-columns:1fr 1fr;gap:4px 24px;margin:16px 0}.certGrid p{margin:5px 0}.certSig{margin-top:30px!important}.certSig:before{display:none!important}.certSig img{display:block;max-width:260px;max-height:85px;object-fit:contain;margin:0 auto 3px}.certFoot{position:absolute;left:30mm;right:30mm;bottom:13mm;text-align:center;border-top:1px solid #ccc;padding-top:6px;font-size:9px;color:#555}}
#printArea{display:none}
</style>
</head>
<body>
<header class="top"><div class="brand"><div class="logo">VEX</div><div><h1>A2B by VEX</h1><small>Operación en campo · v1.6</small></div></div></header>
<main class="wrap">
<section id="home" class="view active">
  <div class="hero"><h2>¿Qué necesitas hacer?</h2><p>Todo está pensado para terminar un servicio y entregar documentos sin meterse a menús raros.</p><span id="nextCert" class="nextfolio"></span> <button class="btn small" style="margin-left:6px" onclick="installVex()">Instalar app</button></div>
  <div class="grid" id="kpis"></div>
  <div class="actions">
    <button class="action primary" onclick="openService()">＋ Nuevo servicio<small>Registrar y terminar</small></button>
    <button class="action" onclick="openQuote()">$ Cotización<small>Precio final automático</small></button>
    <button class="action" onclick="openRemission()">▤ Nota de remisión<small>Cobro / comprobante</small></button>
    <button class="action" onclick="go('certs');focusCert()">▣ Certificado<small>Folio automático</small></button>
  </div>
  <div class="card"><h3>Servicios recientes</h3><div id="homeServices" class="list"></div></div>
  <div class="card"><h3>Pendiente de facturar</h3><div id="homeBilling" class="list"></div></div>
</section>
<section id="services" class="view"><div class="toolbar"><button class="btn primary" onclick="openService()">＋ Nuevo servicio</button></div><div id="serviceList" class="list"></div></section>
<section id="clients" class="view"><div class="toolbar"><button class="btn primary" onclick="openClient()">＋ Cliente</button><button class="btn" onclick="openTech()">＋ Técnico</button><button class="btn" onclick="openSettings()">⚙ Configuración</button></div><div id="clientList" class="list"></div><div class="card"><h3>Técnicos</h3><div id="techList" class="list"></div></div></section>
<section id="billing" class="view"><div class="toolbar"><button class="btn primary" onclick="openQuote()">＋ Cotización</button><button class="btn" onclick="openRemission()">＋ Nota de remisión</button></div><div class="card"><h3>Cotizaciones</h3><div id="quoteList" class="list"></div></div><div class="card"><h3>Notas de remisión</h3><div id="remissionList" class="list"></div></div><div class="card"><h3>Facturas / CFDI</h3><p class="subtle">Guarda aquí el PDF y XML timbrados. Puedes compartirlos juntos por WhatsApp.</p><div id="invoiceList" class="list"></div></div><div class="card"><h3>Contratos de servicio</h3><div id="contractList" class="list"></div></div></section>
<section id="certs" class="view"><div class="card"><h3>Certificado rápido</h3><p class="subtle">No se emite si falta un dato o la firma del responsable. El folio se asigna solo al generar.</p><form id="certForm"><input type="hidden" name="clientId"><input type="hidden" name="serviceId"><div class="field"><label>Nombre / cliente *</label><input name="name" required></div><div class="row"><div class="field"><label>Fecha del servicio *</label><input type="date" name="serviceDate" required></div><div class="field"><label>Vigencia *</label><input name="validity" placeholder="Ej. 30 días" required></div></div><div class="field"><label>Domicilio *</label><textarea name="address" required></textarea></div><div class="field"><label>Técnico que realizó el servicio *</label><select name="technicianName" id="certTech" required></select></div><div class="field"><label>Producto aplicado *</label><input name="productApplied" placeholder="Ej. Demand Duo" required></div><div class="field"><label>Ingrediente activo *</label><input name="activeIngredient" required></div><div class="field"><label>Registro COFEPRIS *</label><input name="cofeprisReg" required></div><button class="btn primary block">Generar certificado</button></form><p class="hint">* Todos los campos son obligatorios. La firma se configura una sola vez en Clientes → Configuración.</p></div><div class="card"><h3>Certificados generados</h3><div id="certList" class="list"></div></div></section>
</main>
<nav class="nav"><button class="active" data-view="home" onclick="go('home')"><b>⌂</b>Inicio</button><button data-view="services" onclick="go('services')"><b>▤</b>Servicios</button><button data-view="clients" onclick="go('clients')"><b>♙</b>Clientes</button><button data-view="billing" onclick="go('billing')"><b>$</b>Documentos</button><button data-view="certs" onclick="go('certs')"><b>▣</b>Certif.</button></nav>
<dialog id="dlg"><div class="modal"><div class="modalhead"><h2 id="dlgTitle"></h2><button class="close" onclick="dlg.close()">×</button></div><div id="dlgBody"></div></div></dialog>
<div id="printArea"></div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/4.2.1/jspdf.umd.min.js"></script>
<script>
const KEY='vexServiciosMotoV1';
const defaults={settings:{companyName:'VEX Control de Plagas',companyPhone:'618 160 1000',licenseNumber:'24-10R0024',responsibleName:'Eduardo A. García Serrano',responsibleTitle:'Responsable sanitario',signatureData:'',vatRate:.16,isrRate:.0125,productCode:'72102103',unitCode:'E48',description:'Servicio de control de plagas',certPrefix:'VEX-CERT-',remPrefix:'VEX-NR-',quotePrefix:'VEX-COT-',seqCert:1048,seqService:0,seqQuote:0,seqRemission:0,seqInvoice:0,seqContract:0,contractPrefix:'VEX-CON-',lastProduct:{productApplied:'',activeIngredient:'',cofeprisReg:''},aspelBridgeUrl:'',aspelBridgeToken:'',aspelAdmUrl:'https://adm.aspel.com.mx/'},clients:[],techs:[{id:'TEC-001',name:'Eduardo A. García Serrano',phone:'',active:true}],services:[],quotes:[],remissions:[],invoices:[],certificates:[],contracts:[]};
function load(){let x;try{x=JSON.parse(localStorage.getItem(KEY)||'null')}catch{};x=x||structuredClone(defaults);x.settings={...defaults.settings,...(x.settings||{})};for(const k of ['clients','techs','services','quotes','remissions','invoices','certificates','contracts'])if(!Array.isArray(x[k]))x[k]=[];if(!x.techs.length)x.techs=structuredClone(defaults.techs);return x}
let db=load();
// Si A2B se abre desde el mismo Bridge, toma automáticamente URL/token del setup.
try{
  const boot=JSON.parse(localStorage.getItem('a2bBridgeBootstrap')||'null');
  if(boot){
    if(boot.url) db.settings.aspelBridgeUrl=boot.url;
    if(boot.token) db.settings.aspelBridgeToken=boot.token;
    localStorage.removeItem('a2bBridgeBootstrap');
    localStorage.setItem(KEY,JSON.stringify(db));
  }else if(!db.settings.aspelBridgeUrl && /^https?:$/.test(location.protocol)){
    db.settings.aspelBridgeUrl=location.origin;
    localStorage.setItem(KEY,JSON.stringify(db));
  }
}catch{}
const h=s=>String(s??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
const money=n=>Number(n||0).toLocaleString('es-MX',{style:'currency',currency:'MXN'});
const today=()=>new Date().toISOString().slice(0,10);
function save(){localStorage.setItem(KEY,JSON.stringify(db));render()}
function id(prefix,seq){db.settings[seq]=(db.settings[seq]||0)+1;return prefix+db.settings[seq]}
function folio(prefix,seq,n){return prefix+String(n??db.settings[seq]??0).padStart(4,'0')}
function modal(title,body){dlgTitle.textContent=title;dlgBody.innerHTML=body;dlg.showModal()}
function go(v){document.querySelectorAll('.view').forEach(x=>x.classList.toggle('active',x.id===v));document.querySelectorAll('.nav button').forEach(x=>x.classList.toggle('active',x.dataset.view===v));window.scrollTo({top:0,behavior:'smooth'});render()}
function clientOpts(sel=''){return `<option value="">— Sin registrar —</option>`+db.clients.map(c=>`<option value="${c.id}" ${c.id===sel?'selected':''}>${h(c.name)}</option>`).join('')}
function techOpts(sel=''){return db.techs.filter(t=>t.active!==false).map(t=>`<option value="${t.id}" ${t.id===sel?'selected':''}>${h(t.name)}</option>`).join('')}
function personLabel(x){return x==='moral'?'Persona moral':'Persona física'}
function taxCalc(amount,mode,withISR,withIVA){const vat=db.settings.vatRate,isr=withISR?db.settings.isrRate:0,ivaRet=withIVA?(2/3*vat):0,factor=1+vat-isr-ivaRet;const subtotal=mode==='final'?amount/factor:amount,iva=subtotal*vat,retISR=subtotal*isr,retIVA=subtotal*ivaRet,total=subtotal+iva-retISR-retIVA;return{subtotal,iva,retISR,retIVA,total}}
function render(){
 nextCert.textContent='Siguiente certificado: '+db.settings.certPrefix+(db.settings.seqCert+1);if(window.certTech){const current=certTech.value;certTech.innerHTML='<option value="">Selecciona técnico</option>'+db.techs.filter(t=>t.active!==false).map(t=>`<option value="${h(t.name)}">${h(t.name)}</option>`).join('');if(current)certTech.value=current;}
 kpis.innerHTML=`<div class="kpi"><span>Servicios</span><b>${db.services.length}</b></div><div class="kpi"><span>Por facturar</span><b>${db.services.filter(s=>!s.invoiceId&&Number(s.amount)>0).length}</b></div><div class="kpi"><span>Certificados</span><b>${db.certificates.length}</b></div><div class="kpi"><span>Órdenes cerradas</span><b>${db.services.filter(s=>s.status==='CERRADO').length}</b></div>`;
 const recent=[...db.services].reverse().slice(0,5);homeServices.innerHTML=recent.length?recent.map(serviceItem).join(''):'<div class="empty">Todavía no hay servicios.</div>';
 const pending=[...db.services].filter(s=>!s.invoiceId&&Number(s.amount)>0).reverse().slice(0,5);homeBilling.innerHTML=pending.length?pending.map(s=>`<div class="item"><div class="main"><b>${h(s.clientName)}</b><small>${h(s.date)} · ${money(s.amount)}</small></div><button class="btn small primary" onclick="billService('${s.id}')">Facturar</button></div>`).join(''):'<div class="empty">Todo al día.</div>';
 serviceList.innerHTML=db.services.length?[...db.services].reverse().map(serviceItem).join(''):'<div class="empty">Sin servicios.</div>';
 clientList.innerHTML=db.clients.length?db.clients.map(c=>`<div class="item"><div class="main"><b>${h(c.name)}</b><small>WhatsApp: ${h(c.whatsapp||c.phone||'Sin número')} ${c.rfc?'· RFC '+h(c.rfc):''}</small><div class="pillbar" style="margin-top:7px"><button class="pill" onclick="openClient('${c.id}')">Editar</button>${c.whatsapp||c.phone?`<button class="pill" onclick="openWhatsAppForClient('${c.id}','Hola ${h(c.name)}, te contactamos de VEX Control de Plagas.')">WhatsApp</button>`:''}</div></div><span class="badge">${personLabel(c.personType)}</span></div>`).join(''):'<div class="empty">Agrega los clientes frecuentes una sola vez.</div>';
 techList.innerHTML=db.techs.map(t=>`<div class="item"><div class="main"><b>${h(t.name)}</b><small>${h(t.phone||'')}</small></div><span class="badge good">ACTIVO</span></div>`).join('');
 quoteList.innerHTML=db.quotes.length?[...db.quotes].reverse().map(q=>`<div class="item"><div class="main"><b>${h(q.folio||q.id)} · ${h(q.clientName)}</b><small>${h(q.date||'')} · ${money(q.tax?.total)} · ${h(q.status||'BORRADOR')}</small></div><div><button class="btn small" onclick="printQuote('${q.id}')">PDF</button> <button class="btn small" onclick="shareDoc('quote','${q.id}')">WhatsApp</button> <button class="btn small primary" onclick="invoiceQuote('${q.id}')">Facturar</button></div></div>`).join(''):'<div class="empty">Sin cotizaciones.</div>';
 remissionList.innerHTML=db.remissions.length?[...db.remissions].reverse().map(r=>`<div class="item"><div class="main"><b>${h(r.folio)} · ${h(r.clientName)}</b><small>${h(r.date)} · ${money(r.total)} · ${h(r.paymentStatus)}</small></div><div><button class="btn small" onclick="printRemission('${r.id}')">PDF</button> <button class="btn small" onclick="shareDoc('remission','${r.id}')">WhatsApp</button></div></div>`).join(''):'<div class="empty">Sin notas de remisión.</div>';
 invoiceList.innerHTML=db.invoices.length?[...db.invoices].reverse().map(i=>`<div class="item"><div class="main"><b>${h(i.fiscalFolio||i.id)} · ${h(i.clientName)}</b><small>${money(i.tax?.total)} · ${h(i.status)}${i.uuid?' · UUID '+h(i.uuid):''}</small><div class="pillbar" style="margin-top:6px"><span class="badge ${i.hasPdf?'good':'red'}">PDF ${i.hasPdf?'✓':'—'}</span><span class="badge ${i.hasXml?'good':'red'}">XML ${i.hasXml?'✓':'—'}</span></div></div><div><button class="btn small" onclick="showPacket('${i.id}')">Abrir</button> <button class="btn small" onclick="attachInvoiceFiles('${i.id}')">Adjuntar CFDI</button> <button class="btn small primary" onclick="shareInvoice('${i.id}')">WhatsApp</button></div></div>`).join(''):'<div class="empty">Aún no hay facturas preparadas.</div>';
 certList.innerHTML=db.certificates.length?[...db.certificates].reverse().map(c=>`<div class="item"><div class="main"><b>${h(c.folio)} · ${h(c.name)}</b><small>${h(c.serviceDate)} · ${h(c.address)}</small></div><div><button class="btn small" onclick="printCert('${c.id}')">PDF</button> <button class="btn small" onclick="shareDoc('certificate','${c.id}')">WhatsApp</button></div></div>`).join(''):'<div class="empty">Sin certificados.</div>';
 contractList.innerHTML=db.contracts.length?[...db.contracts].reverse().map(c=>`<div class="item"><div class="main"><b>${h(c.folio)} · ${h(c.clientName)}</b><small>${h(c.startDate)} · ${h(c.frequency)} · ${money(c.amount)}</small></div><div><button class="btn small" onclick="printContract('${c.id}')">PDF</button> <button class="btn small" onclick="shareDoc('contract','${c.id}')">WhatsApp</button></div></div>`).join(''):'<div class="empty">Sin contratos.</div>';
}
function serviceItem(s){return `<div class="item"><div class="main"><b>${h(s.clientName)}</b><small>${h(s.date)} ${s.time?'· '+h(s.time):''} · ${h(s.serviceType||'Servicio')} ${s.amount?'· '+money(s.amount):''}</small><div class="pillbar" style="margin-top:8px"><button class="pill" onclick="serviceDocs('${s.id}')">${s.status==='CERRADO'?'Documentos':'Cerrar / documentos'}</button>${!s.invoiceId&&s.amount?`<button class="pill" onclick="billService('${s.id}')">Facturar</button>`:''}${s.clientId?`<button class="pill" onclick="whatsService('${s.id}')">WhatsApp</button>`:''}</div></div><span class="badge ${s.status==='CERRADO'?'good':''}">${h(s.status||'PROGRAMADO')}</span></div>`}
function openClient(cid=''){const ex=db.clients.find(x=>x.id===cid)||{};modal(ex.id?'Editar cliente':'Nuevo cliente',`<form id="fClient"><div class="field"><label>Nombre comercial *</label><input name="name" required value="${h(ex.name||'')}"></div><div class="row"><div class="field"><label>Teléfono</label><input name="phone" inputmode="tel" value="${h(ex.phone||'')}"></div><div class="field"><label>WhatsApp principal *</label><input name="whatsapp" inputmode="tel" required placeholder="6181234567" value="${h(ex.whatsapp||ex.phone||'')}"></div></div><div class="notice success">Canal predeterminado: WhatsApp. Este número se usa para órdenes, certificados, notas, contratos y facturas.</div><div class="field"><label>Domicilio</label><textarea name="address">${h(ex.address||'')}</textarea></div><div class="row"><div class="field"><label>Tipo</label><select name="personType"><option value="fisica" ${ex.personType!=='moral'?'selected':''}>Persona física</option><option value="moral" ${ex.personType==='moral'?'selected':''}>Persona moral</option></select></div><div class="field"><label>RFC</label><input name="rfc" value="${h(ex.rfc||'')}"></div></div><div class="field"><label>Razón social</label><input name="legalName" value="${h(ex.legalName||'')}"></div><div class="row"><div class="field"><label>CP fiscal</label><input name="fiscalZip" inputmode="numeric" value="${h(ex.fiscalZip||'')}"></div><div class="field"><label>Régimen fiscal</label><input name="fiscalRegime" placeholder="Ej. 601" value="${h(ex.fiscalRegime||'')}"></div></div><div class="field"><label>Uso CFDI</label><input name="cfdiUse" value="${h(ex.cfdiUse||'G03')}"></div><button class="btn primary block">Guardar cliente</button></form>`);fClient.onsubmit=e=>{e.preventDefault();const o=Object.fromEntries(new FormData(e.target));o.id=ex.id||'CLI-'+Date.now();const i=db.clients.findIndex(x=>x.id===o.id);o.waLink='https://wa.me/'+waDigits(o.whatsapp||o.phone);if(i>=0)db.clients[i]=o;else db.clients.push(o);save();dlg.close()}}
function openTech(){modal('Nuevo técnico',`<form id="fTech"><div class="field"><label>Nombre</label><input name="name" required></div><div class="field"><label>Teléfono</label><input name="phone"></div><button class="btn primary block">Guardar técnico</button></form>`);fTech.onsubmit=e=>{e.preventDefault();const o=Object.fromEntries(new FormData(e.target));o.id='TEC-'+Date.now();o.active=true;db.techs.push(o);save();dlg.close()}}
function openService(pref={}){const lp=db.settings.lastProduct||{};modal('Nuevo servicio',`<form id="fService"><div class="field"><label>Cliente</label><select name="clientId" id="sClient">${clientOpts(pref.clientId)}</select></div><div class="field"><label>Nombre si no está registrado</label><input name="clientName" value="${h(pref.clientName||'')}"></div><div class="field"><label>Domicilio</label><textarea name="address" required>${h(pref.address||'')}</textarea></div><div class="row"><div class="field"><label>Fecha</label><input type="date" name="date" value="${pref.date||today()}" required></div><div class="field"><label>Hora</label><input type="time" name="time"></div></div><div class="field"><label>Técnico</label><select name="technicianId" required>${techOpts()}</select></div><div class="field"><label>Servicio</label><input name="serviceType" value="${h(pref.serviceType||'Control de plagas')}"></div><div class="notice">Producto: si es el mismo del último servicio, ya aparece lleno. Solo corrígelo cuando cambie.</div><div class="field"><label>Producto aplicado</label><input name="productApplied" required value="${h(pref.productApplied||lp.productApplied||'')}"></div><div class="field"><label>Ingrediente activo</label><input name="activeIngredient" required value="${h(pref.activeIngredient||lp.activeIngredient||'')}"></div><div class="field"><label>Registro COFEPRIS</label><input name="cofeprisReg" required value="${h(pref.cofeprisReg||lp.cofeprisReg||'')}"></div><div class="field"><label>Importe pactado (total final)</label><input type="number" step="0.01" name="amount" inputmode="decimal" value="${pref.amount||''}"></div><button class="btn primary block">Guardar servicio</button></form>`);const f=fService;sClient.onchange=()=>{const c=db.clients.find(x=>x.id===sClient.value);if(c){f.clientName.value=c.name;f.address.value=c.address||''}};f.onsubmit=e=>{e.preventDefault();const o=Object.fromEntries(new FormData(f));const c=db.clients.find(x=>x.id===o.clientId),t=db.techs.find(x=>x.id===o.technicianId);o.id=id('SER-','seqService');o.clientName=o.clientName||c?.name||'Sin cliente';o.address=o.address||c?.address||'';o.technicianName=t?.name||'';o.amount=Number(o.amount||0);o.status='PROGRAMADO';db.services.push(o);db.settings.lastProduct={productApplied:o.productApplied,activeIngredient:o.activeIngredient,cofeprisReg:o.cofeprisReg};save();dlg.close();serviceDocs(o.id)}}
function serviceDocs(sid){const s=db.services.find(x=>x.id===sid);if(!s)return;const closed=s.status==='CERRADO';modal('Servicio · '+s.clientName,`<div class="notice ${closed?'success':''}"><b>${closed?'Orden cerrada':'Orden pendiente de cierre'}</b><br>${closed?'Firma del cliente registrada. Los documentos ya se pueden entregar.':'El técnico debe cerrar la orden y recolectar la firma del cliente.'}</div><div class="tax"><div class="taxline"><span>Fecha</span><b>${h(s.date)}</b></div><div class="taxline"><span>Técnico</span><b>${h(s.technicianName||'')}</b></div><div class="taxline"><span>Total</span><b>${s.amount?money(s.amount):'Sin importe'}</b></div>${s.signedBy?`<div class="taxline"><span>Firmó cliente</span><b>${h(s.signedBy)}</b></div>`:''}</div>${!closed?`<button class="btn primary block" style="margin-top:10px" onclick="closeService('${s.id}')">✓ Cerrar orden y recolectar firma</button>`:`<div class="doc-actions"><button class="btn primary" onclick="printServiceOrder('${s.id}')">▤ Orden de servicio</button><button class="btn" onclick="certFromService('${s.id}');dlg.close()">▣ Certificado</button><button class="btn" onclick="remissionFromService('${s.id}')">Nota de remisión</button><button class="btn" onclick="openContract('${s.id}')">Contrato formal</button><button class="btn green" onclick="billService('${s.id}')">$ Facturar</button><button class="btn blue" onclick="deliveryCenter('${s.id}')">📤 Centro de entrega</button><button class="btn" onclick="whatsService('${s.id}')">WhatsApp cliente</button></div>`}`)}
let closeSigDirty=false,closeSigCtx=null;
function closeService(sid){const s=db.services.find(x=>x.id===sid);if(!s)return;const c=db.clients.find(x=>x.id===s.clientId)||{};modal('Cerrar orden de servicio',`<div class="notice">Verifica el trabajo, captura observaciones y pide al cliente firmar de conformidad.</div><form id="fClose"><div class="field"><label>Resultado *</label><select name="result" required><option value="REALIZADO">Realizado</option><option value="REALIZADO_CON_OBSERVACIONES">Realizado con observaciones</option></select></div><div class="field"><label>Observaciones / recomendaciones</label><textarea name="observations" placeholder="Ej. Se recomienda sellar acceso en área de almacén."></textarea></div><div class="row"><div class="field"><label>Nombre de quien firma *</label><input name="signedBy" required value="${h(c.contactName||'')}"></div><div class="field"><label>Cargo</label><input name="signedRole" placeholder="Gerente / encargado"></div></div><label class="check"><input type="checkbox" name="conformity" required> El cliente confirma que el servicio fue realizado y recibe las recomendaciones.</label><div class="card"><h3>Firma del cliente *</h3><canvas id="closeSigPad" width="560" height="180" style="width:100%;height:130px;border:1px solid #d1d5db;border-radius:12px;background:#fff;touch-action:none"></canvas><button type="button" class="btn block" onclick="clearCloseSig()">Limpiar firma</button></div><button class="btn primary block">Cerrar orden</button></form>`);setTimeout(initCloseSig,30);fClose.onsubmit=e=>{e.preventDefault();if(!closeSigDirty){alert('Falta la firma del cliente.');return}const o=Object.fromEntries(new FormData(fClose)),canvas=document.getElementById('closeSigPad'),t=trimCanvas(canvas);if(!t){alert('No pude detectar la firma.');return}s.result=o.result;s.observations=o.observations||'';s.signedBy=o.signedBy;s.signedRole=o.signedRole||'';s.clientSignatureData=t.toDataURL('image/png');s.closedAt=new Date().toISOString();s.status='CERRADO';save();dlg.close();serviceDocs(sid)}}
function initCloseSig(){const c=document.getElementById('closeSigPad');if(!c)return;closeSigDirty=false;closeSigCtx=c.getContext('2d');closeSigCtx.lineWidth=4;closeSigCtx.lineCap='round';closeSigCtx.strokeStyle='#111';const pos=e=>{const r=c.getBoundingClientRect();return{x:(e.clientX-r.left)*c.width/r.width,y:(e.clientY-r.top)*c.height/r.height}};c.onpointerdown=e=>{e.preventDefault();closeSigDirty=true;c.setPointerCapture?.(e.pointerId);const q=pos(e);closeSigCtx.beginPath();closeSigCtx.moveTo(q.x,q.y)};c.onpointermove=e=>{if(!closeSigDirty||!(e.buttons||e.pressure>0))return;e.preventDefault();const q=pos(e);closeSigCtx.lineTo(q.x,q.y);closeSigCtx.stroke()}}
function clearCloseSig(){const c=document.getElementById('closeSigPad');if(c)c.getContext('2d').clearRect(0,0,c.width,c.height);closeSigDirty=false}
function printServiceOrder(sid){const s=db.services.find(x=>x.id===sid);if(!s||s.status!=='CERRADO')return alert('Primero cierra la orden.');const sig=s.clientSignatureData||'';printArea.innerHTML=`<div class="doc"><div class="docHead"><div><div class="docBrand">VEX</div><b>Control de Plagas</b></div><div class="docMeta"><b>ORDEN DE SERVICIO</b><br>${h(s.id)}<br>${h(s.date)}</div></div><h1>${h(s.clientName)}</h1><p><b>Domicilio:</b> ${h(s.address)}</p><p><b>Técnico:</b> ${h(s.technicianName)} &nbsp; <b>Servicio:</b> ${h(s.serviceType)}</p><table><tbody><tr><th>Producto</th><td>${h(s.productApplied)}</td></tr><tr><th>Ingrediente activo</th><td>${h(s.activeIngredient)}</td></tr><tr><th>Registro COFEPRIS</th><td>${h(s.cofeprisReg)}</td></tr><tr><th>Resultado</th><td>${h(s.result||'REALIZADO')}</td></tr><tr><th>Observaciones</th><td>${h(s.observations||'Sin observaciones')}</td></tr></tbody></table><div class="sig">${sig?`<img src="${sig}" style="max-width:240px;max-height:80px;display:block;margin:0 auto 4px">`:''}<b>${h(s.signedBy)}</b><br>${h(s.signedRole||'Cliente / encargado')}<br>Recibí de conformidad</div></div>`;setTimeout(()=>window.print(),80)}
function openQuote(clientId='',pref={}){const c=db.clients.find(x=>x.id===clientId);modal('Nueva cotización',`<form id="fQuote"><div class="field"><label>Cliente</label><select name="clientId" id="qClient">${clientOpts(clientId)}</select></div><div class="field"><label>Nombre si no está registrado</label><input name="clientName" value="${h(pref.clientName||'')}"></div><div class="row"><div class="field"><label>Receptor</label><select name="personType" id="qType"><option value="fisica">Persona física</option><option value="moral">Persona moral</option></select></div><div class="field"><label>El importe es</label><select name="mode"><option value="final">Total que quiero cobrar</option><option value="subtotal">Subtotal</option></select></div></div><div class="field"><label>Importe</label><input type="number" step="0.01" inputmode="decimal" name="amount" value="${pref.amount||''}" required></div><div class="field"><label>Concepto</label><textarea name="description">${h(pref.description||db.settings.description)}</textarea></div><label class="check"><input type="checkbox" name="withISR"> Retener ISR 1.25% (RESICO → persona moral)</label><label class="check"><input type="checkbox" name="withIVA"> Retención IVA especial (solo si corresponde)</label><div id="qPreview" class="tax"></div><button class="btn primary block">Guardar y generar cotización</button></form>`);const f=fQuote,type=qType;type.value=c?.personType||pref.personType||'fisica';function sync(){const cl=db.clients.find(x=>x.id===qClient.value);if(cl){type.value=cl.personType;f.clientName.value=cl.name}f.withISR.checked=type.value==='moral';preview()}function preview(){const x=taxCalc(Number(f.amount.value||0),f.mode.value,f.withISR.checked,f.withIVA.checked);qPreview.innerHTML=`<div class="taxline"><span>Base</span><b>${money(x.subtotal)}</b></div><div class="taxline"><span>IVA 16%</span><b>+ ${money(x.iva)}</b></div><div class="taxline"><span>ISR retenido</span><b>${x.retISR?'- '+money(x.retISR):'-'}</b></div>${x.retIVA?`<div class="taxline"><span>IVA retenido</span><b>- ${money(x.retIVA)}</b></div>`:''}<div class="taxline total"><span>Total</span><span>${money(x.total)}</span></div>`}qClient.onchange=sync;type.onchange=()=>{f.withISR.checked=type.value==='moral';preview()};['amount','mode','withISR','withIVA'].forEach(n=>f[n].addEventListener('input',preview));sync();f.onsubmit=e=>{e.preventDefault();const o=Object.fromEntries(new FormData(f)),cl=db.clients.find(x=>x.id===o.clientId);const n=(db.settings.seqQuote||0)+1;db.settings.seqQuote=n;o.id='COT-'+n;o.folio=db.settings.quotePrefix+String(n).padStart(4,'0');o.date=today();o.clientName=o.clientName||cl?.name||'Público general';o.withISR=f.withISR.checked;o.withIVA=f.withIVA.checked;o.amount=Number(o.amount);o.tax=taxCalc(o.amount,o.mode,o.withISR,o.withIVA);o.status='COTIZADA';db.quotes.push(o);save();dlg.close();printQuote(o.id)}}
function printQuote(qid){const q=db.quotes.find(x=>x.id===qid);if(!q)return;printArea.innerHTML=`<div class="doc"><div class="docHead"><div><div class="docBrand">VEX</div><b>Control de Plagas</b></div><div class="docMeta"><b>COTIZACIÓN</b><br>${h(q.folio||q.id)}<br>Fecha: ${h(q.date||today())}</div></div><h1>${h(q.clientName)}</h1><h2>Cotización de servicio</h2><table><thead><tr><th>Descripción</th><th>Cant.</th><th>Importe</th></tr></thead><tbody><tr><td>${h(q.description)}</td><td>1</td><td>${money(q.tax.subtotal)}</td></tr></tbody></table><div class="totals"><div><span>Subtotal</span><b>${money(q.tax.subtotal)}</b></div><div><span>IVA 16%</span><b>${money(q.tax.iva)}</b></div>${q.tax.retISR?`<div><span>Ret. ISR</span><b>-${money(q.tax.retISR)}</b></div>`:''}${q.tax.retIVA?`<div><span>Ret. IVA</span><b>-${money(q.tax.retIVA)}</b></div>`:''}<div class="grand"><span>Total</span><span>${money(q.tax.total)}</span></div></div><p style="margin-top:30px">Precios expresados en MXN. Cotización sujeta a confirmación de alcance y condiciones del servicio.</p></div>`;setTimeout(()=>window.print(),80)}
function openRemission(clientId='',pref={}){modal('Nueva nota de remisión',`<form id="fRem"><input type="hidden" name="serviceId" value="${h(pref.serviceId||'')}"><div class="field"><label>Cliente</label><select name="clientId" id="rClient">${clientOpts(clientId)}</select></div><div class="field"><label>Nombre si no está registrado</label><input name="clientName" value="${h(pref.clientName||'')}"></div><div class="field"><label>Fecha</label><input type="date" name="date" value="${pref.date||today()}" required></div><div class="field"><label>Concepto</label><textarea name="description" required>${h(pref.description||db.settings.description)}</textarea></div><div class="field"><label>Total</label><input type="number" step="0.01" name="total" value="${pref.total||''}" inputmode="decimal" required></div><div class="row"><div class="field"><label>Forma de pago</label><select name="paymentForm"><option>Transferencia</option><option>Efectivo</option><option>Tarjeta</option><option>Por cobrar</option></select></div><div class="field"><label>Estado</label><select name="paymentStatus"><option>PAGADO</option><option>PENDIENTE</option></select></div></div><button class="btn primary block">Generar nota</button></form>`);const f=fRem;rClient.onchange=()=>{const c=db.clients.find(x=>x.id===rClient.value);if(c)f.clientName.value=c.name};f.onsubmit=e=>{e.preventDefault();const o=Object.fromEntries(new FormData(f)),c=db.clients.find(x=>x.id===o.clientId);const n=(db.settings.seqRemission||0)+1;db.settings.seqRemission=n;o.id='NR-'+n;o.folio=db.settings.remPrefix+String(n).padStart(4,'0');o.clientName=o.clientName||c?.name||'Cliente';o.total=Number(o.total);db.remissions.push(o);save();dlg.close();printRemission(o.id)}}
function remissionFromService(sid){const s=db.services.find(x=>x.id===sid);if(!s)return;dlg.close();openRemission(s.clientId,{serviceId:s.id,clientName:s.clientName,date:s.date,description:s.serviceType||db.settings.description,total:s.amount})}
function printRemission(rid){const r=db.remissions.find(x=>x.id===rid);if(!r)return;printArea.innerHTML=`<div class="doc"><div class="docHead"><div><div class="docBrand">VEX</div><b>Control de Plagas</b></div><div class="docMeta"><b>NOTA DE REMISIÓN</b><br>${h(r.folio)}<br>Fecha: ${h(r.date)}</div></div><h1>${h(r.clientName)}</h1><table><thead><tr><th>Descripción</th><th>Importe</th></tr></thead><tbody><tr><td>${h(r.description)}</td><td>${money(r.total)}</td></tr></tbody></table><div class="totals"><div class="grand"><span>TOTAL</span><span>${money(r.total)}</span></div></div><p><b>Forma de pago:</b> ${h(r.paymentForm)} &nbsp;&nbsp; <b>Estado:</b> ${h(r.paymentStatus)}</p><div class="sig"><b>Recibí de conformidad</b><br>Nombre y firma</div></div>`;setTimeout(()=>window.print(),80)}
let contractSigDirty=false,contractSigCtx=null;
function openContract(sid){const s=db.services.find(x=>x.id===sid);if(!s)return;if(s.status!=='CERRADO')return alert('Primero cierra la orden y recolecta la firma del cliente.');const c=db.clients.find(x=>x.id===s.clientId)||{};const existing=db.contracts.find(x=>x.serviceId===sid);if(existing)return printContract(existing.id);const end=new Date();end.setFullYear(end.getFullYear()+1);modal('Contrato de servicio',`<form id="fContract"><div class="notice">Contrato formal de prestación de servicios. Revisa duración y frecuencia antes de firmar.</div><div class="row"><div class="field"><label>Inicio *</label><input type="date" name="startDate" required value="${today()}"></div><div class="field"><label>Terminación *</label><input type="date" name="endDate" required value="${end.toISOString().slice(0,10)}"></div></div><div class="field"><label>Frecuencia *</label><select name="frequency" required><option>Semanal</option><option>Quincenal</option><option selected>Mensual</option><option>Bimestral</option><option>Servicio único</option></select></div><div class="field"><label>Alcance *</label><textarea name="scope" required>${h(s.serviceType||'Servicio profesional de control de plagas')}</textarea></div><div class="row"><div class="field"><label>Importe por servicio *</label><input type="number" step="0.01" name="amount" required value="${Number(s.amount||0)}"></div><div class="field"><label>Condición de pago *</label><select name="paymentTerms"><option>Pago al servicio</option><option>7 días</option><option>15 días</option><option>30 días</option></select></div></div><div class="row"><div class="field"><label>Firmante cliente *</label><input name="signedBy" required value="${h(s.signedBy||'')}"></div><div class="field"><label>Cargo</label><input name="signedRole" value="${h(s.signedRole||'')}"></div></div><label class="check"><input type="checkbox" name="accept" required> El cliente acepta las condiciones del contrato y autoriza la prestación del servicio.</label><div class="card"><h3>Firma de aceptación *</h3><canvas id="contractSigPad" width="560" height="180" style="width:100%;height:130px;border:1px solid #d1d5db;border-radius:12px;background:#fff;touch-action:none"></canvas><button type="button" class="btn block" onclick="clearContractSig()">Limpiar firma</button></div><button class="btn primary block">Generar contrato</button></form>`);setTimeout(initContractSig,30);fContract.onsubmit=e=>{e.preventDefault();if(!contractSigDirty)return alert('Falta la firma de aceptación.');const o=Object.fromEntries(new FormData(fContract)),t=trimCanvas(document.getElementById('contractSigPad'));if(!t)return alert('No pude detectar la firma.');const n=(db.settings.seqContract||0)+1;db.settings.seqContract=n;o.id='CON-'+n;o.folio=db.settings.contractPrefix+String(n).padStart(4,'0');o.serviceId=s.id;o.clientId=s.clientId;o.clientName=s.clientName;o.address=s.address;o.amount=Number(o.amount);o.signatureData=t.toDataURL('image/png');o.companySignatureData=db.settings.signatureData||'';o.createdAt=new Date().toISOString();db.contracts.push(o);save();dlg.close();printContract(o.id)}}
function initContractSig(){const c=document.getElementById('contractSigPad');if(!c)return;contractSigDirty=false;contractSigCtx=c.getContext('2d');contractSigCtx.lineWidth=4;contractSigCtx.lineCap='round';contractSigCtx.strokeStyle='#111';const pos=e=>{const r=c.getBoundingClientRect();return{x:(e.clientX-r.left)*c.width/r.width,y:(e.clientY-r.top)*c.height/r.height}};c.onpointerdown=e=>{e.preventDefault();contractSigDirty=true;c.setPointerCapture?.(e.pointerId);const q=pos(e);contractSigCtx.beginPath();contractSigCtx.moveTo(q.x,q.y)};c.onpointermove=e=>{if(!(e.buttons||e.pressure>0))return;e.preventDefault();const q=pos(e);contractSigCtx.lineTo(q.x,q.y);contractSigCtx.stroke()}}
function clearContractSig(){const c=document.getElementById('contractSigPad');if(c)c.getContext('2d').clearRect(0,0,c.width,c.height);contractSigDirty=false}
function printContract(cid){const c=db.contracts.find(x=>x.id===cid);if(!c)return;printArea.innerHTML=`<div class="doc"><div class="docHead"><div><div class="docBrand">VEX</div><b>Control de Plagas</b></div><div class="docMeta"><b>CONTRATO DE PRESTACIÓN DE SERVICIOS</b><br>${h(c.folio)}<br>${h(c.startDate)}</div></div><h1>Contrato de servicio de control de plagas</h1><p>Celebran por una parte <b>VEX Control de Plagas</b>, y por la otra <b>${h(c.clientName)}</b>, respecto del inmueble ubicado en ${h(c.address)}.</p><p><b>PRIMERA. Objeto.</b> VEX prestará ${h(c.scope)} con una frecuencia ${h(c.frequency)}.</p><p><b>SEGUNDA. Vigencia.</b> Del ${h(c.startDate)} al ${h(c.endDate)}.</p><p><b>TERCERA. Contraprestación.</b> ${money(c.amount)} MXN por servicio, bajo condición de pago: ${h(c.paymentTerms)}.</p><p><b>CUARTA. Obligaciones de VEX.</b> Ejecutar el servicio con personal designado, registrar los productos aplicados y emitir la documentación operativa correspondiente.</p><p><b>QUINTA. Obligaciones del cliente.</b> Facilitar acceso a las áreas acordadas, informar condiciones relevantes del inmueble, seguir recomendaciones de seguridad y cubrir los importes convenidos.</p><p><b>SEXTA. Alcance.</b> El control de plagas es un proceso técnico sujeto a condiciones ambientales, sanitarias y de infraestructura; las recomendaciones correctivas forman parte del servicio.</p><p><b>SÉPTIMA. Terminación.</b> Cualquiera de las partes podrá solicitar la terminación por incumplimiento o por acuerdo escrito, sin perjuicio de servicios ya realizados y pendientes de pago.</p><p><b>OCTAVA. Aceptación.</b> Las partes manifiestan haber leído y aceptado las condiciones anteriores.</p><div class="row" style="margin-top:28px"><div class="sig">${c.companySignatureData?`<img src="${c.companySignatureData}" style="max-width:220px;max-height:70px;display:block;margin:0 auto 3px">`:''}<b>${h(db.settings.responsibleName)}</b><br>VEX Control de Plagas</div><div class="sig">${c.signatureData?`<img src="${c.signatureData}" style="max-width:220px;max-height:70px;display:block;margin:0 auto 3px">`:''}<b>${h(c.signedBy)}</b><br>${h(c.signedRole||'Cliente')}</div></div></div>`;setTimeout(()=>window.print(),80)}
function billService(sid){const s=db.services.find(x=>x.id===sid);if(!s)return;if(!s.amount){dlg.close();openQuote(s.clientId,{clientName:s.clientName,description:s.serviceType});return}const c=db.clients.find(x=>x.id===s.clientId);if(!c){alert('Para facturar fácil, registra primero los datos fiscales del cliente.');dlg.close();openQuote('',{clientName:s.clientName,amount:s.amount,description:s.serviceType});return}const n=(db.settings.seqQuote||0)+1;db.settings.seqQuote=n;const q={id:'COT-'+n,folio:db.settings.quotePrefix+String(n).padStart(4,'0'),date:today(),clientId:c.id,clientName:c.name,personType:c.personType,amount:Number(s.amount),mode:'final',description:s.serviceType,withISR:c.personType==='moral',withIVA:false,status:'BORRADOR',serviceId:s.id};q.tax=taxCalc(q.amount,q.mode,q.withISR,q.withIVA);db.quotes.push(q);invoiceQuote(q.id);s.invoiceId=db.invoices.at(-1)?.id;save()}
function invoiceQuote(qid){const q=db.quotes.find(x=>x.id===qid);if(!q)return;let inv=db.invoices.find(x=>x.quoteId===qid);if(!inv){const c=db.clients.find(x=>x.id===q.clientId)||{};inv={id:id('FAC-','seqInvoice'),quoteId:qid,clientId:q.clientId||'',serviceId:q.serviceId||'',clientName:q.clientName,customer:{name:c.legalName||c.name||q.clientName,rfc:c.rfc||'',fiscalZip:c.fiscalZip||'',fiscalRegime:c.fiscalRegime||'',cfdiUse:c.cfdiUse||'G03'},tax:q.tax,description:q.description,productCode:db.settings.productCode,unitCode:db.settings.unitCode,paymentMethod:'PUE',paymentForm:'03',status:'PREPARADA_PARA_ASPEL',hasPdf:false,hasXml:false,uuid:'',fiscalFolio:''};db.invoices.push(inv);q.status='PREPARADA_PARA_ASPEL';save()}showPacket(inv.id)}
function invoicePacket(i){return{invoice:i.id,status:i.status,customer:i.customer,concept:{productCode:i.productCode,unitCode:i.unitCode,description:i.description,quantity:1,unitPrice:Number(i.tax.subtotal.toFixed(6)),vatPercent:16,isrRetentionPercent:i.tax.retISR?1.25:0},payment:{method:i.paymentMethod,form:i.paymentForm},totals:i.tax,callback:{invoiceId:i.id,serviceId:i.serviceId||''}}}
function showPacket(iid){const i=db.invoices.find(x=>x.id===iid);if(!i)return;const p=invoicePacket(i),bridge=String(db.settings.aspelBridgeUrl||'').trim();modal('Factura / CFDI',`<div class="notice ${i.status==='TIMBRADA'?'success':''}"><b>${i.status==='TIMBRADA'?'CFDI timbrado':'Lista para Aspel'}</b><br>${bridge?'Puente configurado: '+h(bridge):'Modo semiautomático: abre Aspel, timbra y adjunta aquí PDF/XML. Cuando montemos el Bridge, este mismo botón enviará y recuperará el CFDI.'}</div><div class="tax"><div class="taxline"><span>Cliente</span><b>${h(p.customer.name)}</b></div><div class="taxline"><span>RFC</span><b>${h(p.customer.rfc||'FALTA')}</b></div><div class="taxline"><span>Clave SAT</span><b>${p.concept.productCode}</b></div><div class="taxline"><span>Base Aspel</span><b>${money(p.totals.subtotal)}</b></div><div class="taxline total"><span>Total</span><span>${money(p.totals.total)}</span></div>${i.uuid?`<div class="taxline"><span>UUID</span><b>${h(i.uuid)}</b></div>`:''}${i.fiscalFolio?`<div class="taxline"><span>Folio fiscal</span><b>${h(i.fiscalFolio)}</b></div>`:''}</div><div class="toolbar"><button class="btn primary" onclick="sendToAspelBridge('${i.id}')">${bridge?'Enviar al puente Aspel':'Abrir Aspel ADM'}</button>${bridge?`<button class="btn" onclick="syncAspelBridge('${i.id}')">Sincronizar</button>`:''}<button class="btn" onclick="attachInvoiceFiles('${i.id}')">Adjuntar PDF / XML</button><button class="btn blue" onclick="shareInvoice('${i.id}')">Compartir WhatsApp</button></div><pre class="code" id="jsonPacket">${h(JSON.stringify(p,null,2))}</pre><button class="btn block" onclick="copyPacket()">Copiar paquete Aspel</button>`)}

function deliveryCenter(sid){
 const s=db.services.find(x=>x.id===sid);if(!s)return;
 if(s.status!=='CERRADO')return closeService(sid);
 const c=clientOfId(s.clientId),cert=db.certificates.find(x=>x.serviceId===sid),rem=db.remissions.find(x=>x.serviceId===sid),con=db.contracts.find(x=>x.serviceId===sid),inv=db.invoices.find(x=>x.serviceId===sid);
 const line=(name,state,actions)=>`<div class="item"><div class="main"><b>${name}</b><small>${state}</small></div><div>${actions}</div></div>`;
 const ready='<span class="badge good">LISTO</span>',missing='<span class="badge red">FALTA</span>';
 modal('Entregar documentación',`<div class="notice success"><b>${h(s.clientName)}</b><br>WhatsApp: ${h(c?.whatsapp||c?.phone||'Sin número guardado')}<br>Desde aquí el técnico entrega todo sin buscar archivos.</div><div class="list">
 ${line('Orden de servicio','Cerrada y firmada',`<button class="btn small primary" onclick="shareDoc('order','${s.id}')">Compartir PDF</button>`)}
 ${line('Certificado',cert?cert.folio:'Aún no generado',cert?`<button class="btn small primary" onclick="shareDoc('certificate','${cert.id}')">Compartir PDF</button>`:`<button class="btn small" onclick="certFromService('${s.id}');dlg.close()">Generar</button>`)}
 ${line('Nota de remisión',rem?rem.folio:'Aún no generada',rem?`<button class="btn small primary" onclick="shareDoc('remission','${rem.id}')">Compartir PDF</button>`:`<button class="btn small" onclick="remissionFromService('${s.id}')">Generar</button>`)}
 ${line('Contrato',con?con.folio:'Opcional / no generado',con?`<button class="btn small primary" onclick="shareDoc('contract','${con.id}')">Compartir PDF</button>`:`<button class="btn small" onclick="openContract('${s.id}')">Generar</button>`)}
 ${line('Factura / CFDI',inv?(inv.status==='TIMBRADA'?'Timbrada'+(inv.hasPdf?' · PDF':'')+(inv.hasXml?' · XML':''):'Preparada para Aspel'):'Aún no preparada',inv?`${inv.hasPdf||inv.hasXml?`<button class="btn small primary" onclick="shareInvoice('${inv.id}')">Compartir CFDI</button>`:''} <button class="btn small" onclick="showPacket('${inv.id}')">Abrir</button>`:`<button class="btn small" onclick="billService('${s.id}')">Preparar</button>`)}
 </div><div class="divider"></div><button class="btn blue block" onclick="shareServiceBundle('${s.id}')">📤 Compartir todos los PDFs listos</button><button class="btn block" style="margin-top:8px" onclick="whatsService('${s.id}')">Abrir chat del cliente</button><p class="hint">Android mostrará el selector de compartir. El número guardado sirve para abrir inmediatamente el chat correcto; una PWA no puede adjuntar archivos silenciosamente a un chat específico sin WhatsApp Business API.</p>`);
}
async function shareServiceBundle(sid){
 try{
  const s=db.services.find(x=>x.id===sid);if(!s||s.status!=='CERRADO')throw new Error('Primero cierra la orden.');
  const specs=[['order',s.id]];
  const cert=db.certificates.find(x=>x.serviceId===sid),rem=db.remissions.find(x=>x.serviceId===sid),con=db.contracts.find(x=>x.serviceId===sid),inv=db.invoices.find(x=>x.serviceId===sid);
  if(cert)specs.push(['certificate',cert.id]);if(rem)specs.push(['remission',rem.id]);if(con)specs.push(['contract',con.id]);
  const files=[];for(const [type,id] of specs){const p=makePdf(type,id),blob=p.doc.output('blob');files.push(new File([blob],p.name,{type:'application/pdf'}))}
  if(inv){const pf=await getInvoiceFile(inv.id,'pdf'),xf=await getInvoiceFile(inv.id,'xml');if(pf?.blob)files.push(new File([pf.blob],pf.name||`Factura_${inv.id}.pdf`,{type:pf.blob.type||'application/pdf'}));if(xf?.blob)files.push(new File([xf.blob],xf.name||`Factura_${inv.id}.xml`,{type:xf.blob.type||'application/xml'}))}
  const c=clientOfId(s.clientId),text=`Hola ${c?.name||s.clientName}. Te compartimos la documentación de tu servicio VEX del ${s.date}.`;
  if(navigator.share && navigator.canShare?.({files})){await navigator.share({files,title:`Documentos VEX - ${s.clientName}`,text});return}
  for(const f of files){const a=document.createElement('a');a.href=URL.createObjectURL(f);a.download=f.name;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1200)}
  if(c)openWhatsAppForClient(c.id,text+' Los documentos se descargaron en el teléfono para adjuntarlos.');else alert('Documentos descargados.');
 }catch(e){alert(e.message||'No pude preparar los documentos.')}
}
function waDigits(v){let d=String(v||'').replace(/\D/g,'');if(d.length===10)d='52'+d;return d}
function clientOfId(id){return db.clients.find(x=>x.id===id)||null}
function openWhatsAppForClient(cid,text=''){const c=clientOfId(cid);if(!c)return alert('Cliente no encontrado.');const n=waDigits(c.whatsapp||c.phone);if(!n)return alert('Agrega el WhatsApp del cliente.');window.open(`https://wa.me/${n}?text=${encodeURIComponent(text||'Hola, te contactamos de VEX Control de Plagas.')}`,'_blank')}
function whatsService(sid){const s=db.services.find(x=>x.id===sid);if(!s)return;const c=clientOfId(s.clientId);if(!c)return alert('Registra al cliente y su WhatsApp primero.');const text=`Hola ${c.name}. Te contactamos de VEX Control de Plagas respecto al servicio del ${s.date}. Enseguida te compartimos la documentación correspondiente.`;openWhatsAppForClient(c.id,text)}
function docClient(type,id){let o;if(type==='order'){o=db.services.find(x=>x.id===id);return clientOfId(o?.clientId)}if(type==='quote'){o=db.quotes.find(x=>x.id===id)}if(type==='remission'){o=db.remissions.find(x=>x.id===id)}if(type==='certificate'){o=db.certificates.find(x=>x.id===id)}if(type==='contract'){o=db.contracts.find(x=>x.id===id)}return clientOfId(o?.clientId)}
function pdfHeader(doc,title,folio,date){doc.setTextColor(180,16,22);doc.setFont('helvetica','bold');doc.setFontSize(24);doc.text('VEX',15,18);doc.setTextColor(30,30,30);doc.setFontSize(10);doc.text('Control de Plagas',15,24);doc.setFontSize(13);doc.text(title,195,16,{align:'right'});doc.setFontSize(9);doc.text(String(folio||''),195,22,{align:'right'});doc.text(String(date||today()),195,27,{align:'right'});doc.setDrawColor(180,16,22);doc.setLineWidth(.8);doc.line(15,31,195,31);return 40}
function pdfLines(doc,label,value,y){doc.setFont('helvetica','bold');doc.setFontSize(9);doc.text(label,15,y);doc.setFont('helvetica','normal');const lines=doc.splitTextToSize(String(value||''),145);doc.text(lines,50,y);return y+Math.max(7,lines.length*5)}
function addPdfSig(doc,data,name,role,x,y){if(data){try{doc.addImage(data,'PNG',x,y,55,20,undefined,'FAST')}catch{}}doc.setDrawColor(80);doc.line(x,y+22,x+60,y+22);doc.setFontSize(8);doc.text(String(name||''),x+30,y+27,{align:'center'});doc.text(String(role||''),x+30,y+31,{align:'center'})}
function makePdf(type,id){if(!window.jspdf?.jsPDF)throw new Error('El generador PDF no cargó. Conéctate a internet y vuelve a abrir la app.');const {jsPDF}=window.jspdf,doc=new jsPDF({unit:'mm',format:'a4'});let o,y;if(type==='order'){o=db.services.find(x=>x.id===id);if(!o||o.status!=='CERRADO')throw new Error('Primero cierra la orden.');y=pdfHeader(doc,'ORDEN DE SERVICIO',o.id,o.date);doc.setFontSize(16);doc.setFont('helvetica','bold');doc.text(o.clientName,15,y);y+=10;y=pdfLines(doc,'Domicilio:',o.address,y);y=pdfLines(doc,'Técnico:',o.technicianName,y);y=pdfLines(doc,'Servicio:',o.serviceType,y);y=pdfLines(doc,'Producto:',o.productApplied,y);y=pdfLines(doc,'Ingrediente activo:',o.activeIngredient,y);y=pdfLines(doc,'Registro COFEPRIS:',o.cofeprisReg,y);y=pdfLines(doc,'Resultado:',o.result||'REALIZADO',y);y=pdfLines(doc,'Observaciones:',o.observations||'Sin observaciones',y);addPdfSig(doc,o.clientSignatureData,o.signedBy,o.signedRole||'Cliente / encargado',75,230);return{doc,name:`Orden_${o.id}_${safeFile(o.clientName)}.pdf`,text:`Orden de servicio ${o.id} de VEX Control de Plagas.`}}
if(type==='quote'){o=db.quotes.find(x=>x.id===id);y=pdfHeader(doc,'COTIZACIÓN',o.folio,o.date);doc.setFontSize(16);doc.setFont('helvetica','bold');doc.text(o.clientName,15,y);y+=12;y=pdfLines(doc,'Concepto:',o.description,y);y=pdfLines(doc,'Subtotal:',money(o.tax.subtotal),y);y=pdfLines(doc,'IVA 16%:',money(o.tax.iva),y);if(o.tax.retISR)y=pdfLines(doc,'Ret. ISR:',`- ${money(o.tax.retISR)}`,y);if(o.tax.retIVA)y=pdfLines(doc,'Ret. IVA:',`- ${money(o.tax.retIVA)}`,y);doc.setFontSize(15);doc.text(`TOTAL: ${money(o.tax.total)}`,15,y+8);return{doc,name:`Cotizacion_${o.folio}.pdf`,text:`Cotización ${o.folio} de VEX Control de Plagas por ${money(o.tax.total)}.`}}
if(type==='remission'){o=db.remissions.find(x=>x.id===id);y=pdfHeader(doc,'NOTA DE REMISIÓN',o.folio,o.date);doc.setFontSize(16);doc.setFont('helvetica','bold');doc.text(o.clientName,15,y);y+=12;y=pdfLines(doc,'Concepto:',o.description,y);y=pdfLines(doc,'Forma de pago:',o.paymentForm,y);y=pdfLines(doc,'Estado:',o.paymentStatus,y);doc.setFontSize(15);doc.text(`TOTAL: ${money(o.total)}`,15,y+8);return{doc,name:`Nota_${o.folio}.pdf`,text:`Nota de remisión ${o.folio} de VEX Control de Plagas por ${money(o.total)}.`}}
if(type==='certificate'){o=db.certificates.find(x=>x.id===id);y=pdfHeader(doc,'CONSTANCIA DE SERVICIO',o.folio,o.serviceDate);doc.setFontSize(11);doc.text('Se hace constar la realización de un servicio profesional de control de plagas a:',15,y);y+=9;doc.setFontSize(16);doc.setFont('helvetica','bold');doc.text(o.name,15,y);y+=11;y=pdfLines(doc,'Domicilio:',o.address,y);y=pdfLines(doc,'Vigencia:',o.validity,y);y=pdfLines(doc,'Técnico:',o.technicianName,y);y=pdfLines(doc,'Producto:',o.productApplied,y);y=pdfLines(doc,'Ingrediente activo:',o.activeIngredient,y);y=pdfLines(doc,'Registro COFEPRIS:',o.cofeprisReg,y);y=pdfLines(doc,'Licencia:',o.licenseNumber||db.settings.licenseNumber,y);addPdfSig(doc,o.signatureData||db.settings.signatureData,o.responsibleName||db.settings.responsibleName,o.responsibleTitle||db.settings.responsibleTitle,75,225);return{doc,name:`Certificado_${o.folio}.pdf`,text:`Certificado ${o.folio} de VEX Control de Plagas.`}}
if(type==='contract'){o=db.contracts.find(x=>x.id===id);y=pdfHeader(doc,'CONTRATO DE PRESTACIÓN DE SERVICIOS',o.folio,o.startDate);doc.setFontSize(10);const clauses=[`Celebran VEX Control de Plagas y ${o.clientName}, respecto del inmueble ubicado en ${o.address}.`,`PRIMERA. Objeto. VEX prestará ${o.scope} con frecuencia ${o.frequency}.`,`SEGUNDA. Vigencia. Del ${o.startDate} al ${o.endDate}.`,`TERCERA. Contraprestación. ${money(o.amount)} MXN por servicio. Condición: ${o.paymentTerms}.`,`CUARTA. VEX ejecutará el servicio con personal designado, registrará productos aplicados y emitirá la documentación operativa correspondiente.`,`QUINTA. El cliente facilitará el acceso, informará condiciones relevantes, seguirá las recomendaciones de seguridad y cubrirá los importes convenidos.`,`SEXTA. El control de plagas es un proceso técnico sujeto a condiciones ambientales, sanitarias y de infraestructura; las recomendaciones correctivas forman parte del servicio.`,`SÉPTIMA. La relación podrá terminar por incumplimiento o acuerdo escrito, sin afectar servicios ya realizados y pendientes de pago.`,`OCTAVA. Las partes manifiestan haber leído y aceptado estas condiciones.`];for(const t of clauses){const lines=doc.splitTextToSize(t,180);doc.text(lines,15,y);y+=lines.length*4.5+3}addPdfSig(doc,o.companySignatureData||db.settings.signatureData,db.settings.responsibleName,'VEX Control de Plagas',25,235);addPdfSig(doc,o.signatureData,o.signedBy,o.signedRole||'Cliente',125,235);return{doc,name:`Contrato_${o.folio}.pdf`,text:`Contrato de servicio ${o.folio} de VEX Control de Plagas.`}}
throw new Error('Documento no soportado')}
function safeFile(x){return String(x||'cliente').normalize('NFD').replace(/[\u0300-\u036f]/g,'').replace(/[^a-zA-Z0-9_-]+/g,'_').slice(0,40)}
async function shareDoc(type,id){try{const p=makePdf(type,id),blob=p.doc.output('blob'),file=new File([blob],p.name,{type:'application/pdf'}),c=docClient(type,id),msg=`Hola ${c?.name||''}. ${p.text}`;if(navigator.canShare?.({files:[file]})&&navigator.share){await navigator.share({files:[file],title:p.name,text:msg});return}const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=p.name;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000);if(c)openWhatsAppForClient(c.id,msg+' El PDF se descargó en este teléfono para adjuntarlo.');else alert('PDF descargado.')}catch(e){alert(e.message||'No pude compartir el documento.')}}
function openA2BFileDB(){return new Promise((resolve,reject)=>{const r=indexedDB.open('A2BFiles',1);r.onupgradeneeded=()=>{const d=r.result;if(!d.objectStoreNames.contains('invoiceFiles'))d.createObjectStore('invoiceFiles',{keyPath:'key'})};r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error)})}
async function putInvoiceFile(iid,kind,file){const d=await openA2BFileDB();return new Promise((resolve,reject)=>{const tx=d.transaction('invoiceFiles','readwrite');tx.objectStore('invoiceFiles').put({key:iid+':'+kind,invoiceId:iid,kind,name:file.name||`Factura_${iid}.${kind}`,blob:file,updatedAt:new Date().toISOString()});tx.oncomplete=()=>{d.close();resolve(true)};tx.onerror=()=>{d.close();reject(tx.error)}})}
async function getInvoiceFile(iid,kind){try{const d=await openA2BFileDB();return await new Promise((resolve,reject)=>{const tx=d.transaction('invoiceFiles','readonly'),rq=tx.objectStore('invoiceFiles').get(iid+':'+kind);rq.onsuccess=()=>{d.close();resolve(rq.result||null)};rq.onerror=()=>{d.close();reject(rq.error)}})}catch{return null}}
function fileToBlobFromB64(b64,mime){const clean=String(b64||'').replace(/^data:[^,]+,/,''),bin=atob(clean),u=new Uint8Array(bin.length);for(let i=0;i<bin.length;i++)u[i]=bin.charCodeAt(i);return new Blob([u],{type:mime})}
function extractCfdiMeta(xmlText){try{const d=new DOMParser().parseFromString(xmlText,'application/xml'),comp=d.documentElement,tfd=[...d.getElementsByTagName('*')].find(n=>(n.localName||'').toLowerCase()==='timbrefiscaldigital');return{uuid:tfd?.getAttribute('UUID')||tfd?.getAttribute('Uuid')||'',folio:[comp?.getAttribute('Serie'),comp?.getAttribute('Folio')].filter(Boolean).join('')||comp?.getAttribute('Folio')||''}}catch{return{uuid:'',folio:''}}}
function attachInvoiceFiles(iid){const inv=db.invoices.find(x=>x.id===iid);if(!inv)return;const inp=document.createElement('input');inp.type='file';inp.multiple=true;inp.accept='.pdf,.xml,application/pdf,application/xml,text/xml';inp.onchange=async()=>{let pdf=false,xml=false,meta={};for(const f of [...(inp.files||[])]){const name=f.name.toLowerCase();if(f.type==='application/pdf'||name.endsWith('.pdf')){await putInvoiceFile(iid,'pdf',f);pdf=true}if(f.type.includes('xml')||name.endsWith('.xml')){await putInvoiceFile(iid,'xml',f);xml=true;meta=extractCfdiMeta(await f.text())}}if(pdf)inv.hasPdf=true;if(xml)inv.hasXml=true;if(meta.uuid)inv.uuid=meta.uuid;if(meta.folio)inv.fiscalFolio=meta.folio;if(inv.hasPdf&&inv.hasXml)inv.status='TIMBRADA';save();showPacket(iid);alert('CFDI guardado en A2B. Ya puedes compartir PDF y XML por WhatsApp.')};inp.click()}
async function saveBridgeFile(iid,kind,b64,url,mime,name){let blob=null;if(b64)blob=fileToBlobFromB64(b64,mime);else if(url){const r=await fetch(url);if(!r.ok)throw new Error('No pude descargar '+kind.toUpperCase()+' del puente.');blob=await r.blob()}if(blob){await putInvoiceFile(iid,kind,new File([blob],name,{type:blob.type||mime}));return true}return false}
function bridgeHeaders(){const token=String(db.settings.aspelBridgeToken||'').trim();return {'Content-Type':'application/json',...(token?{'Authorization':'Bearer '+token}:{})}}
async function applyBridgeInvoice(i,x){i.bridgeId=x.bridgeId||x.invoice||i.bridgeId||i.id;i.status=x.status||i.status;i.uuid=x.uuid||i.uuid||'';i.fiscalFolio=x.folio||x.fiscalFolio||i.fiscalFolio||'';if(await saveBridgeFile(i.id,'pdf',x.pdfBase64,x.pdfUrl,'application/pdf',`Factura_${i.fiscalFolio||i.id}.pdf`))i.hasPdf=true;if(await saveBridgeFile(i.id,'xml',x.xmlBase64,x.xmlUrl,'application/xml',`Factura_${i.fiscalFolio||i.id}.xml`))i.hasXml=true;if(i.hasPdf&&i.hasXml)i.status='TIMBRADA';save()}
async function sendToAspelBridge(iid){const i=db.invoices.find(x=>x.id===iid);if(!i)return;const bridge=String(db.settings.aspelBridgeUrl||'').trim();if(!bridge){window.open(db.settings.aspelAdmUrl||'https://adm.aspel.com.mx/','_blank');alert('Aspel se abrió. Timbra el CFDI y luego toca “Adjuntar PDF / XML” en A2B.');return}try{const url=bridge.replace(/\/$/,'')+'/api/invoices';const r=await fetch(url,{method:'POST',headers:bridgeHeaders(),body:JSON.stringify(invoicePacket(i))});const x=await r.json().catch(()=>({}));if(!r.ok)throw new Error(x.error||('Puente Aspel respondió '+r.status));await applyBridgeInvoice(i,x);showPacket(iid);if(i.status==='TIMBRADA')alert('CFDI recibido del puente Aspel. PDF y XML guardados.');else alert('Factura enviada al Bridge. Estado: '+(x.status||'PENDIENTE')+'. Puedes tocar “Sincronizar” después.')}catch(e){alert('No pude conectar con el puente Aspel: '+(e.message||e))}}
async function syncAspelBridge(iid){const i=db.invoices.find(x=>x.id===iid);if(!i)return;const bridge=String(db.settings.aspelBridgeUrl||'').trim();if(!bridge){alert('Configura primero la URL del Bridge.');return}try{const bid=encodeURIComponent(i.bridgeId||i.id),r=await fetch(bridge.replace(/\/$/,'')+'/api/invoices/'+bid,{headers:bridgeHeaders()});const x=await r.json().catch(()=>({}));if(!r.ok)throw new Error(x.error||('Bridge respondió '+r.status));await applyBridgeInvoice(i,x);showPacket(iid);alert(i.status==='TIMBRADA'?'Factura sincronizada. PDF/XML listos.':'Estado Aspel: '+(x.status||i.status));}catch(e){alert('No pude sincronizar: '+(e.message||e))}}
async function shareInvoice(iid){const i=db.invoices.find(x=>x.id===iid);if(!i)return;const c=clientOfId(i.clientId),files=[];const pf=await getInvoiceFile(iid,'pdf'),xf=await getInvoiceFile(iid,'xml');if(pf?.blob)files.push(new File([pf.blob],pf.name||`Factura_${iid}.pdf`,{type:pf.blob.type||'application/pdf'}));if(xf?.blob)files.push(new File([xf.blob],xf.name||`Factura_${iid}.xml`,{type:xf.blob.type||'application/xml'}));const msg=`Hola ${c?.name||i.clientName}. Te compartimos tu factura de VEX Control de Plagas${i.fiscalFolio?' folio '+i.fiscalFolio:''}${i.uuid?' · UUID '+i.uuid:''}.`;if(files.length&&navigator.share&&navigator.canShare?.({files})){try{await navigator.share({files,title:`Factura VEX ${i.fiscalFolio||i.id}`,text:msg});return}catch(e){if(e?.name==='AbortError')return}}if(files.length){for(const f of files){const a=document.createElement('a');a.href=URL.createObjectURL(f);a.download=f.name;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1200)}if(c)openWhatsAppForClient(c.id,msg+' El PDF/XML se descargó en el teléfono para adjuntarlo.');return}if(c)openWhatsAppForClient(c.id,`Hola ${c.name}. Tu factura VEX está ${i.status==='TIMBRADA'?'timbrada, pero falta adjuntar el PDF/XML en A2B':'en preparación'}.`);else alert('Agrega el WhatsApp del cliente.')}
function dataUrlToBlob(data){const [m,b]=data.split(','),mime=(m.match(/:(.*?);/)||[])[1]||'application/pdf',bin=atob(b),a=new Uint8Array(bin.length);for(let i=0;i<bin.length;i++)a[i]=bin.charCodeAt(i);return new Blob([a],{type:mime})}
function copyPacket(){navigator.clipboard?.writeText(jsonPacket.textContent).then(()=>alert('Paquete copiado')).catch(()=>alert('Mantén presionado el paquete para copiarlo.'))}
function focusCert(){setTimeout(()=>certForm.name.focus(),80)}
function certFromService(sid){const s=db.services.find(x=>x.id===sid);go('certs');certForm.clientId.value=s.clientId||'';certForm.serviceId.value=s.id||'';certForm.name.value=s.clientName||'';certForm.serviceDate.value=s.date||'';certForm.address.value=s.address||'';certForm.productApplied.value=s.productApplied||'';certForm.activeIngredient.value=s.activeIngredient||'';certForm.cofeprisReg.value=s.cofeprisReg||'';if(window.certTech){certTech.innerHTML='<option value="">Selecciona técnico</option>'+db.techs.filter(t=>t.active!==false).map(t=>`<option value="${h(t.name)}">${h(t.name)}</option>`).join('');certTech.value=s.technicianName||''}certForm.validity.focus()}
certForm.onsubmit=e=>{e.preventDefault();const o=Object.fromEntries(new FormData(e.target));const req=['name','serviceDate','validity','address','technicianName','productApplied','activeIngredient','cofeprisReg'];const missing=req.filter(k=>!String(o[k]||'').trim());if(missing.length){alert('Faltan datos obligatorios. Revisa todos los campos antes de emitir.');return}if(!db.settings.signatureData){alert('Primero configura la firma del responsable sanitario en Clientes → Configuración.');openSettings();return}db.settings.seqCert=(db.settings.seqCert||1048)+1;o.id='CERT-'+db.settings.seqCert;o.folio=db.settings.certPrefix+db.settings.seqCert;o.licenseNumber=db.settings.licenseNumber;o.responsibleName=db.settings.responsibleName;o.responsibleTitle=db.settings.responsibleTitle;o.signatureData=db.settings.signatureData;db.certificates.push(o);save();e.target.reset();if(window.certTech)certTech.value='';printCert(o.id)};
function printCert(cid){const c=db.certificates.find(x=>x.id===cid);if(!c)return;const sig=c.signatureData||db.settings.signatureData||'';printArea.innerHTML=`<div class="doc certDoc"><div class="folio">Folio: ${h(c.folio)}</div><div class="docBrand">VEX</div><h1>CONSTANCIA DE SERVICIO</h1><h2>CONTROL DE PLAGAS</h2><p>Por medio de la presente se hace constar que se realizó un <b>servicio profesional de control de plagas</b> a:</p><p style="font-size:18px;text-align:center"><b>${h(c.name)}</b></p><div class="certGrid"><p><b>Domicilio:</b><br>${h(c.address)}</p><p><b>Fecha del servicio:</b><br>${h(c.serviceDate)}</p><p><b>Vigencia:</b><br>${h(c.validity)}</p><p><b>Técnico:</b><br>${h(c.technicianName)}</p><p><b>Producto aplicado:</b><br>${h(c.productApplied)}</p><p><b>Ingrediente activo:</b><br>${h(c.activeIngredient)}</p><p><b>Registro COFEPRIS:</b><br>${h(c.cofeprisReg)}</p><p><b>Licencia Sanitaria Federal:</b><br>${h(c.licenseNumber||db.settings.licenseNumber)}</p></div><p>Se expide la presente constancia para los fines que al interesado convengan.</p><div class="sig certSig">${sig?`<img src="${sig}" alt="Firma del responsable sanitario">`:''}<b>${h(c.responsibleName||db.settings.responsibleName)}</b><br>${h(c.responsibleTitle||db.settings.responsibleTitle)} · VEX Control de Plagas</div><div class="certFoot">VEX CONTROL DE PLAGAS · ${h(db.settings.companyPhone||'')} · Licencia Sanitaria Federal ${h(c.licenseNumber||db.settings.licenseNumber||'')}</div></div>`;setTimeout(()=>window.print(),100)}
function openSettings(){modal('Configuración',`<div class="notice">Configura esto una vez. Después tus papás no necesitan entrar aquí durante un servicio.</div><form id="fSettings"><div class="field"><label>Responsable sanitario</label><input name="responsibleName" required value="${h(db.settings.responsibleName||'')}"></div><div class="field"><label>Cargo</label><input name="responsibleTitle" required value="${h(db.settings.responsibleTitle||'Responsable sanitario')}"></div><div class="row"><div class="field"><label>Licencia Sanitaria Federal</label><input name="licenseNumber" required value="${h(db.settings.licenseNumber||'')}"></div><div class="field"><label>Teléfono VEX</label><input name="companyPhone" required value="${h(db.settings.companyPhone||'')}"></div></div><div class="card"><h3>Firma del responsable</h3><p class="subtle">Puedes firmar aquí con el dedo o cargar una imagen de tu firma. Se guarda solo en este dispositivo.</p>${db.settings.signatureData?`<img src="${db.settings.signatureData}" style="display:block;max-width:260px;max-height:100px;margin:8px auto;border-bottom:1px solid #ddd">`:'<div class="notice">⚠ Falta configurar la firma. Sin firma la app no emitirá certificados.</div>'}<canvas id="sigPad" width="560" height="180" style="width:100%;height:130px;border:1px solid #d1d5db;border-radius:12px;background:#fff;touch-action:none"></canvas><div class="toolbar"><button type="button" class="btn" onclick="clearSigPad()">Limpiar</button><button type="button" class="btn primary" onclick="saveSigPad()">Guardar firma dibujada</button><button type="button" class="btn" onclick="pickSignature()">Cargar imagen</button></div></div><div class="card"><h3>Aspel ADM</h3><p class="subtle">Déjalo vacío para modo semiautomático. Cuando montemos el Bridge, pega aquí su URL y A2B enviará el paquete fiscal y recibirá PDF/XML.</p><div class="field"><label>URL del Bridge Aspel</label><input name="aspelBridgeUrl" placeholder="Ej. https://a2b-production.up.railway.app" value="${h(db.settings.aspelBridgeUrl||'')}"></div><div class="field"><label>Token del dispositivo</label><input name="aspelBridgeToken" type="password" autocomplete="off" placeholder="Pega el token que muestra /setup" value="${h(db.settings.aspelBridgeToken||'')}"><div class="hint">El token autoriza este teléfono; la contraseña real de Aspel nunca se guarda aquí.</div></div><div class="field"><label>Acceso web a Aspel ADM</label><input name="aspelAdmUrl" value="${h(db.settings.aspelAdmUrl||'https://adm.aspel.com.mx/')}"></div></div><button class="btn primary block">Guardar configuración</button></form><div class="divider"></div><div class="tax"><div class="taxline"><span>Último certificado</span><b>${db.settings.seqCert}</b></div><div class="taxline"><span>Siguiente</span><b>${db.settings.seqCert+1}</b></div><div class="taxline"><span>Aspel ADM</span><b>${db.settings.aspelBridgeUrl?'Bridge configurado':'Modo semiautomático'}</b></div></div><div class="divider"></div><button class="btn block" onclick="exportBackup()">Exportar respaldo JSON</button><button class="btn block" style="margin-top:8px" onclick="importBackup()">Importar respaldo</button>`);setTimeout(initSigPad,30);fSettings.onsubmit=e=>{e.preventDefault();const o=Object.fromEntries(new FormData(fSettings));Object.assign(db.settings,o);save();dlg.close();alert('Configuración guardada')}}
function exportBackup(){const blob=new Blob([JSON.stringify(db,null,2)],{type:'application/json'}),a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='VEX_RESPALDO_'+today()+'.json';a.click();setTimeout(()=>URL.revokeObjectURL(a.href),500)}
function importBackup(){const inp=document.createElement('input');inp.type='file';inp.accept='.json,application/json';inp.onchange=()=>{const f=inp.files[0];if(!f)return;const r=new FileReader();r.onload=()=>{try{const x=JSON.parse(r.result);localStorage.setItem(KEY,JSON.stringify(x));db=load();render();dlg.close();alert('Respaldo importado')}catch{alert('El archivo no es un respaldo válido')}};r.readAsText(f)};inp.click()}

let sigCtx=null,sigDrawing=false,sigDirty=false;
function initSigPad(){const c=document.getElementById('sigPad');if(!c)return;sigCtx=c.getContext('2d');sigCtx.lineWidth=4;sigCtx.lineCap='round';sigCtx.lineJoin='round';sigCtx.strokeStyle='#111';sigCtx.clearRect(0,0,c.width,c.height);const pos=e=>{const r=c.getBoundingClientRect(),p=e.touches?e.touches[0]:e;return{x:(p.clientX-r.left)*c.width/r.width,y:(p.clientY-r.top)*c.height/r.height}};const start=e=>{e.preventDefault();sigDrawing=true;sigDirty=true;const p=pos(e);sigCtx.beginPath();sigCtx.moveTo(p.x,p.y)};const move=e=>{if(!sigDrawing)return;e.preventDefault();const p=pos(e);sigCtx.lineTo(p.x,p.y);sigCtx.stroke()};const end=e=>{if(!sigDrawing)return;e.preventDefault();sigDrawing=false};c.onpointerdown=start;c.onpointermove=move;c.onpointerup=end;c.onpointercancel=end;c.onpointerleave=end}
function clearSigPad(){const c=document.getElementById('sigPad');if(c){c.getContext('2d').clearRect(0,0,c.width,c.height);sigDirty=false}}
function trimCanvas(src){const ctx=src.getContext('2d'),w=src.width,h=src.height,d=ctx.getImageData(0,0,w,h).data;let minX=w,minY=h,maxX=-1,maxY=-1;for(let y=0;y<h;y++)for(let x=0;x<w;x++){const i=(y*w+x)*4;if(d[i+3]>10 && (d[i]<245||d[i+1]<245||d[i+2]<245)){if(x<minX)minX=x;if(x>maxX)maxX=x;if(y<minY)minY=y;if(y>maxY)maxY=y}}if(maxX<0)return null;const pad=14;minX=Math.max(0,minX-pad);minY=Math.max(0,minY-pad);maxX=Math.min(w-1,maxX+pad);maxY=Math.min(h-1,maxY+pad);const out=document.createElement('canvas');out.width=maxX-minX+1;out.height=maxY-minY+1;out.getContext('2d').drawImage(src,minX,minY,out.width,out.height,0,0,out.width,out.height);return out}
function saveSigPad(){const c=document.getElementById('sigPad');if(!c||!sigDirty){alert('Firma primero en el recuadro.');return}const t=trimCanvas(c);if(!t){alert('No pude detectar la firma.');return}db.settings.signatureData=t.toDataURL('image/png');save();openSettings()}
function pickSignature(){const inp=document.createElement('input');inp.type='file';inp.accept='image/png,image/jpeg,image/webp';inp.onchange=()=>{const f=inp.files&&inp.files[0];if(!f)return;const r=new FileReader();r.onload=()=>{const im=new Image();im.onload=()=>{const maxW=900,maxH=350,sc=Math.min(1,maxW/im.width,maxH/im.height),c=document.createElement('canvas');c.width=Math.max(1,Math.round(im.width*sc));c.height=Math.max(1,Math.round(im.height*sc));c.getContext('2d').drawImage(im,0,0,c.width,c.height);db.settings.signatureData=c.toDataURL('image/png');save();openSettings()};im.src=r.result};r.readAsDataURL(f)};inp.click()}
let deferredInstallPrompt=null;window.addEventListener('beforeinstallprompt',e=>{e.preventDefault();deferredInstallPrompt=e});async function installVex(){if(deferredInstallPrompt){deferredInstallPrompt.prompt();await deferredInstallPrompt.userChoice;deferredInstallPrompt=null}else alert('En Chrome abre el menú ⋮ y elige “Instalar aplicación” o “Agregar a pantalla principal”.')}
if('serviceWorker' in navigator && location.protocol.startsWith('http'))window.addEventListener('load',()=>navigator.serviceWorker.register('./sw.js').catch(()=>{}));

render();
</script>
</body>
</html>

A2BAPPV04_7F2A
RUN mkdir -p /app/public && cat > /app/public/setup.html <<'A2BSETUP'
<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>A2B by VEX · Setup</title><style>
:root{font-family:system-ui,-apple-system,Segoe UI,sans-serif;color:#16181d;background:#f4f5f7}body{margin:0}.top{background:#a71319;color:white;padding:18px}.wrap{max-width:760px;margin:auto;padding:14px}.card{background:white;border:1px solid #e2e4e8;border-radius:16px;padding:15px;margin:12px 0}.row{display:grid;grid-template-columns:1fr 1fr;gap:10px}label{font-size:12px;font-weight:700;display:block;margin:8px 0 4px}input{width:100%;box-sizing:border-box;padding:11px;border:1px solid #cfd3d8;border-radius:10px;font:inherit}button{padding:11px 13px;border:0;border-radius:10px;font-weight:800;background:#a71319;color:white;margin:8px 6px 0 0}.muted{color:#68707c;font-size:12px}.ok{color:#087f5b}.bad{color:#b42318}.code{word-break:break-all;background:#111827;color:#d1fae5;padding:10px;border-radius:10px;font-size:12px}.invoice{border-top:1px solid #eee;padding:10px 0}.hidden{display:none}@media(max-width:600px){.row{grid-template-columns:1fr}}
</style></head><body><div class="top"><b>A2B by VEX</b><div style="font-size:12px;opacity:.8">Aspel Bridge · configuración segura</div></div><div class="wrap">
<div class="card"><h3>1. Entrar al setup</h3><p class="muted">Pega aquí el mismo <b>A2B_SECRET</b> que configuraste en Railway/Render. No se guarda en el navegador.</p><input id="secret" type="password" placeholder="A2B_SECRET"><button onclick="status()">Entrar / actualizar</button><div id="state" class="muted"></div></div>
<div id="private" class="hidden">
<div class="card"><h3>2. Vincular celulares</h3><p class="muted">En A2B: Clientes → Configuración → Aspel ADM. Pega la URL de este servidor y este token.</p><div id="token" class="code"></div><button onclick="copyToken()">Copiar token</button><button onclick="openA2B()">Abrir A2B</button><p class="muted">Este botón vincula automáticamente este navegador con el Bridge y abre la aplicación.</p></div>
<div class="card"><h3>3. Credenciales Aspel</h3><p class="muted">Se cifran con AES-256-GCM antes de escribirse en /data. La contraseña no vuelve a mostrarse.</p><div class="row"><div><label>RFC</label><input id="rfc"></div><div><label>Usuario</label><input id="user"></div></div><label>Contraseña</label><input id="password" type="password"><button onclick="saveCreds()">Guardar cifradas</button><button onclick="pingAspel()">Probar conexión</button><button onclick="testLogin()">Probar inicio de sesión</button><div id="aspelState" class="muted"></div></div>
<div class="card"><h3>Facturas recibidas</h3><p class="muted">Mientras calibramos el timbrado automático de Aspel, las solicitudes quedan aquí sin duplicarse. Puedes completar PDF/XML manualmente y el celular los recupera con “Sincronizar”.</p><div id="invoices"></div></div>
</div></div><script>
const $=id=>document.getElementById(id);let admin='';let last=[];
async function api(path,opt={}){opt.headers={...(opt.headers||{}),'X-A2B-Admin':admin,'Content-Type':'application/json'};const r=await fetch(path,opt),x=await r.json().catch(()=>({}));if(!r.ok)throw new Error(x.error||r.status);return x}
async function status(){admin=$('secret').value.trim();try{const x=await api('/api/admin/status');$('private').classList.remove('hidden');$('state').innerHTML='<span class="ok">Conectado.</span> Aspel '+(x.aspel.configured?'configurado ('+x.aspel.userMasked+')':'sin credenciales');$('token').textContent=x.deviceToken;last=x.invoices||[];renderInvoices()}catch(e){$('private').classList.add('hidden');$('state').innerHTML='<span class="bad">No autorizado: '+e.message+'</span>'}}
function copyToken(){navigator.clipboard.writeText($('token').textContent);}
function openA2B(){const token=$('token').textContent.trim();if(!token){alert('Primero entra al setup para obtener el token.');return}localStorage.setItem('a2bBridgeBootstrap',JSON.stringify({url:location.origin,token}));location.href='/app';}
async function saveCreds(){try{const x=await api('/api/admin/aspel/credentials',{method:'POST',body:JSON.stringify({rfc:$('rfc').value,user:$('user').value,password:$('password').value})});$('password').value='';$('aspelState').innerHTML='<span class="ok">Credenciales cifradas y guardadas para '+x.userMasked+'.</span>';await status()}catch(e){$('aspelState').innerHTML='<span class="bad">'+e.message+'</span>'}}
async function pingAspel(){try{$('aspelState').textContent='Probando conexión ligera con Aspel…';const x=await api('/api/admin/aspel/ping',{method:'POST',body:'{}'});const r=x.result;$('aspelState').innerHTML=r.ok?'<span class="ok">Aspel responde por red. HTTP '+r.status+' · '+r.ms+' ms.</span>':'<span class="bad">No se pudo conectar a Aspel: '+(r.error||('HTTP '+r.status))+'</span>'}catch(e){$('aspelState').innerHTML='<span class="bad">'+e.message+'</span>'}}
async function testLogin(){try{$('aspelState').textContent='Probando Aspel con navegador ligero… puede tardar un poco.';const x=await api('/api/admin/aspel/test-login',{method:'POST',body:'{}'});$('aspelState').innerHTML=x.result.ok?'<span class="ok">'+x.result.note+'</span>':'<span class="bad">'+x.result.note+'</span>'}catch(e){$('aspelState').innerHTML='<span class="bad">'+e.message+'</span>'}}
function esc(s){return String(s??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]))}
function renderInvoices(){$('invoices').innerHTML=last.length?last.map(i=>`<div class="invoice"><b>${esc(i.invoice)}</b> · ${esc(i.status)}<div class="muted">${esc(i.note||'')}</div>${i.status!=='TIMBRADA'?`<details><summary>Completar CFDI manualmente</summary><label>Folio</label><input id="f_${esc(i.bridgeId)}"><label>UUID</label><input id="u_${esc(i.bridgeId)}"><label>PDF</label><input type="file" accept=".pdf,application/pdf" id="p_${esc(i.bridgeId)}"><label>XML</label><input type="file" accept=".xml,application/xml,text/xml" id="x_${esc(i.bridgeId)}"><button onclick="complete('${esc(i.bridgeId)}')">Guardar PDF/XML</button></details>`:''}</div>`).join(''):'<p class="muted">Todavía no llegan facturas.</p>'}
const file64=f=>new Promise((ok,fail)=>{if(!f)return ok('');const r=new FileReader;r.onload=()=>ok(String(r.result).split(',')[1]||'');r.onerror=fail;r.readAsDataURL(f)});
async function complete(id){try{const pdf=$('p_'+id).files[0],xml=$('x_'+id).files[0];const body={folio:$('f_'+id).value,uuid:$('u_'+id).value,pdfBase64:await file64(pdf),xmlBase64:await file64(xml)};await api('/api/admin/invoices/'+encodeURIComponent(id)+'/complete',{method:'POST',body:JSON.stringify(body)});await status();alert('CFDI guardado. En A2B toca Sincronizar.')}catch(e){alert(e.message)}}
</script></body></html>

A2BSETUP
RUN npm install --omit=dev && mkdir -p /data
ENV NODE_ENV=production PORT=3000 DATA_DIR=/data NODE_OPTIONS=--max-old-space-size=128 MALLOC_ARENA_MAX=2
EXPOSE 3000
CMD ["npm","start"]
