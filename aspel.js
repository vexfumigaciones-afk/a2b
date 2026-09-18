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

function sessionStatus(dataDir){const f=files(dataDir).session;if(!fs.existsSync(f))return{saved:false};try{const st=fs.statSync(f);return{saved:true,updatedAt:st.mtime.toISOString()}}catch{return{saved:true}}}
function browserLaunchOptions(){return{headless:true,chromiumSandbox:false,args:['--no-sandbox','--disable-dev-shm-usage','--disable-gpu','--disable-software-rasterizer','--disable-extensions','--disable-background-networking','--disable-component-update','--disable-default-apps','--disable-sync','--disable-translate','--mute-audio','--no-first-run','--no-zygote','--renderer-process-limit=1','--disable-features=IsolateOrigins,site-per-process','--js-flags=--max-old-space-size=128']}}
async function ensureSession(dataDir,admUrl){const creds=getCredentials(dataDir);if(!creds)throw new Error('Primero guarda las credenciales de Aspel en /setup.');let browser=null,context=null;try{browser=await chromium.launch(browserLaunchOptions());let saved=null;try{saved=readEncrypted(files(dataDir).session,'aspel-session')}catch{}context=await browser.newContext({viewport:{width:900,height:650},...(saved?{storageState:saved}:{})});const page=await context.newPage();await page.route('**/*',route=>{const t=route.request().resourceType();if(['image','media','font'].includes(t))return route.abort();return route.continue()});const principal=new URL('/principal.html',admUrl).href;await page.goto(saved?principal:admUrl,{waitUntil:'domcontentloaded',timeout:45000});await page.waitForTimeout(2200);const passVisible=await page.locator('input[type="password"]').first().isVisible().catch(()=>false);const isLogin=/login/i.test(page.url())||passVisible;if(!isLogin){const state=await context.storageState();writeEncrypted(files(dataDir).session,state,'aspel-session');return{ok:true,reused:!!saved,url:page.url(),note:saved?'Sesión Aspel reutilizada correctamente.':'Sesión Aspel activa.'}}}catch(e){const msg=String(e&&e.message||e);if(!/login/i.test(msg))console.warn('ASPEL_SESSION_REUSE',msg)}finally{if(context)await context.close().catch(()=>{});if(browser)await browser.close().catch(()=>{})}const fresh=await testLogin(dataDir,admUrl);if(!fresh.ok)throw new Error(fresh.note||'No se pudo iniciar sesión en Aspel.');return{...fresh,reused:false,note:'Sesión Aspel renovada automáticamente. '+fresh.note}}

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

module.exports = { saveCredentials, credentialStatus, sessionStatus, ensureSession, testLogin, pingAspel, issueInvoice };

