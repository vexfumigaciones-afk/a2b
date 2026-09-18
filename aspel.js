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

function envCredentials() {
  const c = {
    rfc: String(process.env.ASPEL_RFC || '').trim().toUpperCase(),
    user: String(process.env.ASPEL_USER || '').trim(),
    password: String(process.env.ASPEL_PASSWORD || '')
  };
  return c.rfc && c.user && c.password ? c : null;
}

function getCredentials(dataDir) {
  const stored = readEncrypted(files(dataDir).creds, 'aspel-credentials');
  return stored || envCredentials();
}

function credentialStatus(dataDir) {
  const stored = readEncrypted(files(dataDir).creds, 'aspel-credentials');
  const c = stored || envCredentials();
  return c ? { configured: true, rfc: c.rfc || '', userMasked: mask(c.user), source: stored ? 'encrypted-data' : 'render-env' } : { configured: false };
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

// Session Guardian: la sesión de Aspel vive en el Bridge, no en la pestaña /setup.
// Se serializan las renovaciones para evitar abrir dos Chromiums al mismo tiempo.
let ensurePromise = null;
const guardian = {
  timer: null,
  started: false,
  running: false,
  dataDir: '',
  admUrl: '',
  intervalMs: 8 * 60 * 1000,
  lastAttemptAt: '',
  lastOkAt: '',
  lastError: '',
  lastUrl: '',
  lastReused: false
};

function savedSessionStatus(dataDir) {
  const f = files(dataDir).session;
  if (!fs.existsSync(f)) return { saved: false };
  try {
    const st = fs.statSync(f);
    return { saved: true, updatedAt: st.mtime.toISOString() };
  } catch {
    return { saved: true };
  }
}

function guardianRuntimeStatus() {
  return {
    started: guardian.started,
    running: guardian.running,
    intervalMs: guardian.intervalMs,
    lastAttemptAt: guardian.lastAttemptAt || '',
    lastOkAt: guardian.lastOkAt || '',
    lastError: guardian.lastError || '',
    lastUrl: guardian.lastUrl || '',
    lastReused: !!guardian.lastReused,
    nextCheckApprox: guardian.started && guardian.lastAttemptAt
      ? new Date(new Date(guardian.lastAttemptAt).getTime() + guardian.intervalMs).toISOString()
      : ''
  };
}

function sessionStatus(dataDir) {
  return { ...savedSessionStatus(dataDir), guardian: guardianRuntimeStatus() };
}

function browserLaunchOptions(){return{headless:true,chromiumSandbox:false,args:['--no-sandbox','--disable-dev-shm-usage','--disable-gpu','--disable-software-rasterizer','--disable-extensions','--disable-background-networking','--disable-component-update','--disable-default-apps','--disable-sync','--disable-translate','--mute-audio','--no-first-run','--no-zygote','--renderer-process-limit=1','--disable-features=IsolateOrigins,site-per-process','--js-flags=--max-old-space-size=128']}}

async function ensureSessionUnlocked(dataDir,admUrl){
  const creds=getCredentials(dataDir);
  if(!creds)throw new Error('Primero guarda las credenciales de Aspel en /setup.');
  let browser=null,context=null;
  try{
    browser=await chromium.launch(browserLaunchOptions());
    let saved=null;
    try{saved=readEncrypted(files(dataDir).session,'aspel-session')}catch{}
    context=await browser.newContext({viewport:{width:900,height:650},...(saved?{storageState:saved}:{})});
    const page=await context.newPage();
    await page.route('**/*',route=>{
      const t=route.request().resourceType();
      if(['image','media','font'].includes(t))return route.abort();
      return route.continue();
    });
    const principal=new URL('/principal.html',admUrl).href;
    await page.goto(saved?principal:admUrl,{waitUntil:'domcontentloaded',timeout:45000});
    await page.waitForTimeout(2200);
    const passVisible=await page.locator('input[type="password"]').first().isVisible().catch(()=>false);
    const isLogin=/login/i.test(page.url())||passVisible;
    if(!isLogin){
      const state=await context.storageState();
      writeEncrypted(files(dataDir).session,state,'aspel-session');
      return{ok:true,reused:!!saved,url:page.url(),note:saved?'Sesión Aspel reutilizada y refrescada.':'Sesión Aspel activa.'};
    }
  }catch(e){
    const msg=String(e&&e.message||e);
    if(!/login/i.test(msg))console.warn('ASPEL_SESSION_REUSE',msg);
  }finally{
    if(context)await context.close().catch(()=>{});
    if(browser)await browser.close().catch(()=>{});
  }
  const fresh=await testLogin(dataDir,admUrl);
  if(!fresh.ok)throw new Error(fresh.note||'No se pudo iniciar sesión en Aspel.');
  return{...fresh,reused:false,note:'Sesión Aspel renovada automáticamente. '+fresh.note};
}

async function ensureSession(dataDir,admUrl){
  if(ensurePromise)return ensurePromise;
  guardian.running=true;
  guardian.lastAttemptAt=new Date().toISOString();
  ensurePromise=(async()=>{
    try{
      const result=await ensureSessionUnlocked(dataDir,admUrl);
      guardian.lastOkAt=new Date().toISOString();
      guardian.lastError='';
      guardian.lastUrl=result.url||'';
      guardian.lastReused=!!result.reused;
      return result;
    }catch(e){
      guardian.lastError=String(e&&e.message||e);
      throw e;
    }finally{
      guardian.running=false;
      ensurePromise=null;
    }
  })();
  return ensurePromise;
}

function startSessionGuardian(dataDir,admUrl,intervalMs){
  guardian.dataDir=dataDir;
  guardian.admUrl=admUrl;
  guardian.intervalMs=Math.max(2*60*1000,Number(intervalMs||process.env.ASPEL_KEEPALIVE_MS||8*60*1000));
  guardian.started=true;
  if(guardian.timer)clearInterval(guardian.timer);
  const tick=async()=>{
    try{
      if(!getCredentials(dataDir))return;
      await ensureSession(dataDir,admUrl);
    }catch(e){
      console.warn('ASPEL_GUARDIAN',String(e&&e.message||e));
    }
  };
  const warm=setTimeout(tick,5000);
  if(warm.unref)warm.unref();
  guardian.timer=setInterval(tick,guardian.intervalMs);
  if(guardian.timer.unref)guardian.timer.unref();
  return guardianRuntimeStatus();
}

function stopSessionGuardian(){
  if(guardian.timer)clearInterval(guardian.timer);
  guardian.timer=null;
  guardian.started=false;
}

async function pingAspel(admUrl) {
  const started = Date.now();
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 12000);
    const r = await fetch(admUrl, { redirect: 'follow', signal: controller.signal, headers: { 'User-Agent': 'A2B-by-VEX/0.7' } });
    clearTimeout(timer);
    return { ok: r.status >= 200 && r.status < 500, status: r.status, finalUrl: r.url, ms: Date.now() - started };
  } catch (e) {
    return { ok: false, status: 0, finalUrl: admUrl, ms: Date.now() - started, error: String(e && e.message || e) };
  }
}



function normKey(s){return String(s||'').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g,'').replace(/[^a-z0-9]/g,'')}
function firstVal(obj, names){
  if(!obj || typeof obj!=='object') return '';
  const map=new Map(Object.entries(obj).map(([k,v])=>[normKey(k),v]));
  for(const n of names){const v=map.get(normKey(n)); if(v!==undefined && v!==null && String(v).trim()) return String(v).trim();}
  return '';
}
function clientFromObject(o){
  if(!o || typeof o!=='object' || Array.isArray(o)) return null;
  const rfc=firstVal(o,['rfc','RFC','rfcCliente','RFCCliente','registroFederal']);
  const legalName=firstVal(o,['razonSocial','razonsocial','nombreFiscal','denominacion','nombreRazonSocial','nombre']);
  const commercialName=firstVal(o,['nombreComercial','nomComercial','comercial','alias']);
  const phone=firstVal(o,['telefono','tel','telefono1','celular','movil']);
  const email=firstVal(o,['correo','email','correoElectronico']);
  const fiscalZip=firstVal(o,['codigoPostal','cp','codigoPostalFiscal','cpFiscal']);
  const fiscalRegime=firstVal(o,['regimenFiscal','regimen','regimenfiscal']);
  const cfdiUse=firstVal(o,['usoCfdi','usoCFDI','usoComprobante','cfdiUse']);
  const address=firstVal(o,['direccion','domicilio','calle','direccionFiscal']);
  const key=firstVal(o,['id','idCliente','clienteId','clave','claveCliente','codigo']);
  const candidate = rfc || legalName || commercialName;
  if(!candidate) return null;
  if(rfc && !/^[A-ZÑ&]{3,4}\d{6}[A-Z0-9]{3}$/i.test(rfc)) return null;
  return {aspelId:key,rfc:rfc.toUpperCase(),legalName:legalName||commercialName,name:commercialName||legalName,phone,email,fiscalZip,fiscalRegime,cfdiUse,address};
}
function collectClientObjects(node, out, depth=0){
  if(depth>8 || node==null) return;
  if(Array.isArray(node)){for(const x of node) collectClientObjects(x,out,depth+1);return;}
  if(typeof node!=='object') return;
  const c=clientFromObject(node); if(c) out.push(c);
  for(const v of Object.values(node)) if(v && typeof v==='object') collectClientObjects(v,out,depth+1);
}
function dedupeClients(items){
  const m=new Map();
  for(const c of items){
    if(!c || (!c.rfc && !c.legalName && !c.name)) continue;
    const k=(c.rfc||'').toUpperCase() || normKey(c.legalName||c.name);
    const prev=m.get(k)||{};
    const merged={...prev};
    for(const [kk,v] of Object.entries(c)) if(v && !merged[kk]) merged[kk]=v;
    m.set(k,merged);
  }
  return [...m.values()].filter(c=>c.rfc || c.legalName || c.name);
}
async function clickClients(page){
  const menuSelectors=['button[aria-label*="menu" i]','button[title*="menu" i]','a[title*="menu" i]','button:has-text("☰")','button:has-text("»")','.menu-button','.navbar-toggler'];
  let clients=null;
  try{const x=page.getByText(/^Clientes$/i).first(); if(await x.count() && await x.isVisible({timeout:500})) clients=x;}catch{}
  if(!clients){
    for(const sel of menuSelectors){try{const b=page.locator(sel).first(); if(await b.count() && await b.isVisible({timeout:300})){await b.click(); await page.waitForTimeout(700); break;}}catch{}}
    try{const x=page.getByText(/^Clientes$/i).first(); if(await x.count() && await x.isVisible({timeout:1500})) clients=x;}catch{}
  }
  if(clients){await clients.click(); return true;}
  const fallbacks=['a:has-text("Clientes")','button:has-text("Clientes")','[href*="cliente" i]','[onclick*="cliente" i]'];
  for(const sel of fallbacks){try{const x=page.locator(sel).first(); if(await x.count() && await x.isVisible({timeout:500})){await x.click(); return true;}}catch{}}
  return false;
}
async function fetchClients(dataDir, admUrl){
  await ensureSession(dataDir,admUrl);
  let browser=null,context=null;
  const found=[]; const jsonHits=[];
  try{
    browser=await chromium.launch(browserLaunchOptions());
    let saved=null; try{saved=readEncrypted(files(dataDir).session,'aspel-session')}catch{}
    context=await browser.newContext({viewport:{width:1100,height:760},...(saved?{storageState:saved}:{})});
    const page=await context.newPage();
    page.on('response',async r=>{
      try{
        const ct=String(r.headers()['content-type']||'');
        if(/json/i.test(ct) && /client|cliente|catalog/i.test(r.url())){
          const j=await r.json(); jsonHits.push(r.url()); collectClientObjects(j,found);
        }
      }catch{}
    });
    await page.route('**/*',route=>{const t=route.request().resourceType(); if(['image','media','font'].includes(t))return route.abort(); return route.continue();});
    const principal=new URL('/principal.html',admUrl).href;
    await page.goto(principal,{waitUntil:'domcontentloaded',timeout:45000});
    await page.waitForTimeout(1800);
    if(/login/i.test(page.url())){await ensureSession(dataDir,admUrl); throw new Error('ASPEL_SESSION_RETRY_REQUIRED');}
    const clicked=await clickClients(page);
    if(clicked){await page.waitForTimeout(3500); await page.waitForLoadState('networkidle',{timeout:9000}).catch(()=>{});}
    // DOM fallback: toma filas visibles y detecta RFC/nombre si el portal no expuso JSON utilizable.
    const rows=page.locator('table tbody tr, [role="row"]');
    const rc=await rows.count().catch(()=>0);
    for(let i=0;i<Math.min(rc,1000);i++){
      try{
        const row=rows.nth(i); if(!(await row.isVisible({timeout:80})))continue;
        const txt=(await row.innerText()).replace(/\s+/g,' ').trim(); if(!txt)continue;
        const rfc=(txt.toUpperCase().match(/\b[A-ZÑ&]{3,4}\d{6}[A-Z0-9]{3}\b/)||[])[0]||'';
        if(!rfc)continue;
        const cells=await row.locator('td,[role="gridcell"],[role="cell"]').allInnerTexts().catch(()=>[]);
        const clean=cells.map(x=>String(x).replace(/\s+/g,' ').trim()).filter(Boolean);
        const name=clean.find(x=>x!==rfc && !/^\d+$/.test(x))||'';
        found.push({rfc,name,legalName:name});
      }catch{}
    }
    const state=await context.storageState(); writeEncrypted(files(dataDir).session,state,'aspel-session');
    const clients=dedupeClients(found).filter(c=>String(c.rfc||'').toUpperCase()!=='XAXX010101000');
    return {ok:true,clients,count:clients.length,url:page.url(),clickedClients:clicked,jsonSources:jsonHits.length,note:clients.length?`Se detectaron ${clients.length} clientes en Aspel.`:'Aspel abrió el catálogo, pero no pude extraer clientes automáticamente. Puede requerir calibrar el selector del catálogo.'};
  } finally {
    if(context)await context.close().catch(()=>{});
    if(browser)await browser.close().catch(()=>{});
  }
}

async function issueInvoice(dataDir, packet) {
  const session = await ensureSession(dataDir, process.env.ASPEL_ADM_URL || 'https://adm.aspel.com.mx/login.html');
  // La autenticación persistente y la cola ya están resueltas. El flujo de timbrado necesita
  // calibrarse contra la cuenta real de Aspel ADM porque los selectores/campos
  // del portal no están documentados como API pública estable.
  return {
    status: 'PENDING_ASPEL_CALIBRATION',
    note: 'Paquete fiscal recibido. '+(session.note||'Sesión Aspel activa.')+' Falta calibrar el llenado/timbrado real para evitar emitir CFDI incorrectos.',
    aspelSession: 'CONNECTED',
    invoice: packet.invoice
  };
}

module.exports = { saveCredentials, credentialStatus, sessionStatus, guardianRuntimeStatus, startSessionGuardian, stopSessionGuardian, ensureSession, testLogin, pingAspel, fetchClients, issueInvoice };

