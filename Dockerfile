# syntax=docker/dockerfile:1
FROM mcr.microsoft.com/playwright:v1.55.0-noble
WORKDIR /app
RUN mkdir -p /app && cat > /app/package.json <<'A2BPKG'
{
  "name": "a2b-by-vex-bridge",
  "version": "0.2.0",
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
  const browser = await chromium.launch({ headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage'] });
  const context = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const page = await context.newPage();
  const result = { ok: false, url: '', note: '' };
  try {
    await page.goto(admUrl, { waitUntil: 'domcontentloaded', timeout: 60000 });
    const { rfc, user, pass } = await detectLoginFields(page);
    if (!rfc || !user || !pass) {
      result.note = `No pude identificar los tres campos de Aspel (RFC:${!!rfc}, usuario:${!!user}, contraseña:${!!pass}).`;
      await page.screenshot({ path: files(dataDir).screenshot, fullPage: true });
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
      await page.screenshot({ path: files(dataDir).screenshot, fullPage: true });
    }
    return result;
  } finally {
    await browser.close();
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

module.exports = { saveCredentials, credentialStatus, testLogin, issueInvoice };

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
const ASPEL_ADM_URL = process.env.ASPEL_ADM_URL || 'https://adm.aspel.com.mx/';
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

async function handler(req,res){
  if(req.method==='OPTIONS'){res.writeHead(204,cors());return res.end()}
  const u=new URL(req.url,`http://${req.headers.host||'localhost'}`), p=u.pathname;
  if(req.method==='GET'&&p==='/'){res.writeHead(302,{Location:'/setup'});return res.end()}
  if(req.method==='GET'&&p==='/setup')return serveSetup(res);
  if(req.method==='GET'&&p==='/api/health')return json(res,200,{ok:true,service:'A2B by VEX Aspel Bridge',version:'0.2.0',secureConfigured:secretReady()});

  if(p.startsWith('/api/admin/')){
    if(!admin(req))return json(res,401,{error:'ADMIN_UNAUTHORIZED'});
    if(req.method==='GET'&&p==='/api/admin/status')return json(res,200,{ok:true,deviceToken:deviceToken(),aspel:aspel.credentialStatus(DATA_DIR),aspelAdmUrl:ASPEL_ADM_URL,invoices:Object.values(loadInvoices()).map(x=>invoicePublic(x,false)).reverse()});
    if(req.method==='POST'&&p==='/api/admin/aspel/credentials'){
      try{const b=await readBody(req);return json(res,200,{ok:true,...aspel.saveCredentials(DATA_DIR,b)})}catch(e){return json(res,400,{error:e.message})}
    }
    if(req.method==='POST'&&p==='/api/admin/aspel/test-login'){
      try{return json(res,200,{ok:true,result:await aspel.testLogin(DATA_DIR,ASPEL_ADM_URL)})}catch(e){return json(res,500,{error:e.message})}
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
RUN mkdir -p /app/public && cat > /app/public/setup.html <<'A2BSETUP'
<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>A2B by VEX · Setup</title><style>
:root{font-family:system-ui,-apple-system,Segoe UI,sans-serif;color:#16181d;background:#f4f5f7}body{margin:0}.top{background:#a71319;color:white;padding:18px}.wrap{max-width:760px;margin:auto;padding:14px}.card{background:white;border:1px solid #e2e4e8;border-radius:16px;padding:15px;margin:12px 0}.row{display:grid;grid-template-columns:1fr 1fr;gap:10px}label{font-size:12px;font-weight:700;display:block;margin:8px 0 4px}input{width:100%;box-sizing:border-box;padding:11px;border:1px solid #cfd3d8;border-radius:10px;font:inherit}button{padding:11px 13px;border:0;border-radius:10px;font-weight:800;background:#a71319;color:white;margin:8px 6px 0 0}.muted{color:#68707c;font-size:12px}.ok{color:#087f5b}.bad{color:#b42318}.code{word-break:break-all;background:#111827;color:#d1fae5;padding:10px;border-radius:10px;font-size:12px}.invoice{border-top:1px solid #eee;padding:10px 0}.hidden{display:none}@media(max-width:600px){.row{grid-template-columns:1fr}}
</style></head><body><div class="top"><b>A2B by VEX</b><div style="font-size:12px;opacity:.8">Aspel Bridge · configuración segura</div></div><div class="wrap">
<div class="card"><h3>1. Entrar al setup</h3><p class="muted">Pega aquí el mismo <b>A2B_SECRET</b> que configuraste en Railway/Render. No se guarda en el navegador.</p><input id="secret" type="password" placeholder="A2B_SECRET"><button onclick="status()">Entrar / actualizar</button><div id="state" class="muted"></div></div>
<div id="private" class="hidden">
<div class="card"><h3>2. Vincular celulares</h3><p class="muted">En A2B: Clientes → Configuración → Aspel ADM. Pega la URL de este servidor y este token.</p><div id="token" class="code"></div><button onclick="copyToken()">Copiar token</button></div>
<div class="card"><h3>3. Credenciales Aspel</h3><p class="muted">Se cifran con AES-256-GCM antes de escribirse en /data. La contraseña no vuelve a mostrarse.</p><div class="row"><div><label>RFC</label><input id="rfc"></div><div><label>Usuario</label><input id="user"></div></div><label>Contraseña</label><input id="password" type="password"><button onclick="saveCreds()">Guardar cifradas</button><button onclick="testLogin()">Probar inicio de sesión</button><div id="aspelState" class="muted"></div></div>
<div class="card"><h3>Facturas recibidas</h3><p class="muted">Mientras calibramos el timbrado automático de Aspel, las solicitudes quedan aquí sin duplicarse. Puedes completar PDF/XML manualmente y el celular los recupera con “Sincronizar”.</p><div id="invoices"></div></div>
</div></div><script>
const $=id=>document.getElementById(id);let admin='';let last=[];
async function api(path,opt={}){opt.headers={...(opt.headers||{}),'X-A2B-Admin':admin,'Content-Type':'application/json'};const r=await fetch(path,opt),x=await r.json().catch(()=>({}));if(!r.ok)throw new Error(x.error||r.status);return x}
async function status(){admin=$('secret').value.trim();try{const x=await api('/api/admin/status');$('private').classList.remove('hidden');$('state').innerHTML='<span class="ok">Conectado.</span> Aspel '+(x.aspel.configured?'configurado ('+x.aspel.userMasked+')':'sin credenciales');$('token').textContent=x.deviceToken;last=x.invoices||[];renderInvoices()}catch(e){$('private').classList.add('hidden');$('state').innerHTML='<span class="bad">No autorizado: '+e.message+'</span>'}}
function copyToken(){navigator.clipboard.writeText($('token').textContent);}
async function saveCreds(){try{const x=await api('/api/admin/aspel/credentials',{method:'POST',body:JSON.stringify({rfc:$('rfc').value,user:$('user').value,password:$('password').value})});$('password').value='';$('aspelState').innerHTML='<span class="ok">Credenciales cifradas y guardadas para '+x.userMasked+'.</span>';await status()}catch(e){$('aspelState').innerHTML='<span class="bad">'+e.message+'</span>'}}
async function testLogin(){try{$('aspelState').textContent='Probando Aspel… puede tardar un poco.';const x=await api('/api/admin/aspel/test-login',{method:'POST',body:'{}'});$('aspelState').innerHTML=x.result.ok?'<span class="ok">'+x.result.note+'</span>':'<span class="bad">'+x.result.note+'</span>'}catch(e){$('aspelState').innerHTML='<span class="bad">'+e.message+'</span>'}}
function esc(s){return String(s??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]))}
function renderInvoices(){$('invoices').innerHTML=last.length?last.map(i=>`<div class="invoice"><b>${esc(i.invoice)}</b> · ${esc(i.status)}<div class="muted">${esc(i.note||'')}</div>${i.status!=='TIMBRADA'?`<details><summary>Completar CFDI manualmente</summary><label>Folio</label><input id="f_${esc(i.bridgeId)}"><label>UUID</label><input id="u_${esc(i.bridgeId)}"><label>PDF</label><input type="file" accept=".pdf,application/pdf" id="p_${esc(i.bridgeId)}"><label>XML</label><input type="file" accept=".xml,application/xml,text/xml" id="x_${esc(i.bridgeId)}"><button onclick="complete('${esc(i.bridgeId)}')">Guardar PDF/XML</button></details>`:''}</div>`).join(''):'<p class="muted">Todavía no llegan facturas.</p>'}
const file64=f=>new Promise((ok,fail)=>{if(!f)return ok('');const r=new FileReader;r.onload=()=>ok(String(r.result).split(',')[1]||'');r.onerror=fail;r.readAsDataURL(f)});
async function complete(id){try{const pdf=$('p_'+id).files[0],xml=$('x_'+id).files[0];const body={folio:$('f_'+id).value,uuid:$('u_'+id).value,pdfBase64:await file64(pdf),xmlBase64:await file64(xml)};await api('/api/admin/invoices/'+encodeURIComponent(id)+'/complete',{method:'POST',body:JSON.stringify(body)});await status();alert('CFDI guardado. En A2B toca Sincronizar.')}catch(e){alert(e.message)}}
</script></body></html>

A2BSETUP
RUN npm install --omit=dev && mkdir -p /data
ENV NODE_ENV=production PORT=3000 DATA_DIR=/data
EXPOSE 3000
CMD ["npm","start"]
