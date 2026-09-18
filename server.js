const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');
const { requireSecret, deviceToken, adminSessionToken, isAdminSecret, isDeviceToken, isAdminSessionToken, atomicWrite } = require('./crypto-store');
const aspel = require('./aspel');

const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const PUBLIC_DIR = __dirname;
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
function cookies(req){const out={};for(const part of String(req.headers.cookie||'').split(';')){const i=part.indexOf('=');if(i<0)continue;const k=part.slice(0,i).trim(),v=part.slice(i+1).trim();if(k)out[k]=decodeURIComponent(v)}return out}
function cookieHeader(name,value,maxAge){return `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`}
function admin(req) { const c=cookies(req); return secretReady() && (isAdminSecret(req.headers['x-a2b-admin']) || isAdminSessionToken(c.a2b_admin)); }
function device(req) { const c=cookies(req); return secretReady() && (isDeviceToken(bearer(req)) || isDeviceToken(c.a2b_device)); }
function rememberAdmin(req,res){if(isAdminSecret(req.headers['x-a2b-admin']))res.setHeader('Set-Cookie',cookieHeader('a2b_admin',adminSessionToken(),15552000));}
function rememberDevice(req,res){if(isDeviceToken(bearer(req)))res.setHeader('Set-Cookie',cookieHeader('a2b_device',deviceToken(),31536000));}
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
  if(req.method==='GET'&&['/manifest.webmanifest','/sw.js','/icon-192.png','/icon-512.png'].includes(p)){
    const name=p.slice(1), f=path.join(PUBLIC_DIR,name);
    const types={'.webmanifest':'application/manifest+json; charset=utf-8','.js':'application/javascript; charset=utf-8','.png':'image/png'};
    if(!fs.existsSync(f))return json(res,404,{error:'ASSET_NOT_FOUND'});
    const ext=path.extname(name);
    const data=fs.readFileSync(f);
    res.writeHead(200,cors({'Content-Type':types[ext]||'application/octet-stream','Content-Length':data.length,'Cache-Control':'public, max-age=3600'}));
    return res.end(data);
  }
  if(req.method==='GET'&&p==='/api/health')return json(res,200,{ok:true,service:'A2B by VEX Aspel Bridge',version:'1.2.0',secureConfigured:secretReady(),aspelGuardian:aspel.guardianRuntimeStatus()});

  if(p.startsWith('/api/admin/')){
    if(!admin(req))return json(res,401,{error:'ADMIN_UNAUTHORIZED'});
    rememberAdmin(req,res);
    if(req.method==='GET'&&p==='/api/admin/status')return json(res,200,{ok:true,deviceToken:deviceToken(),aspel:aspel.credentialStatus(DATA_DIR),session:aspel.sessionStatus(DATA_DIR),aspelAdmUrl:ASPEL_ADM_URL,invoices:Object.values(loadInvoices()).map(x=>invoicePublic(x,false)).reverse()});
    if(req.method==='POST'&&p==='/api/admin/aspel/credentials'){
      try{
        const b=await readBody(req), saved=aspel.saveCredentials(DATA_DIR,b);
        setTimeout(()=>aspel.ensureSession(DATA_DIR,ASPEL_ADM_URL).catch(e=>console.warn('ASPEL_AUTO_LOGIN',e.message)),100).unref?.();
        return json(res,200,{ok:true,...saved,guardian:aspel.guardianRuntimeStatus()});
      }catch(e){return json(res,400,{error:e.message})}
    }
    if(req.method==='GET'&&p==='/api/admin/runtime'){
      const m=process.memoryUsage();
      return json(res,200,{ok:true,version:'1.2.0',memoryMB:{rss:Math.round(m.rss/1048576),heapUsed:Math.round(m.heapUsed/1048576),external:Math.round(m.external/1048576)}});
    }
    if(req.method==='POST'&&p==='/api/admin/aspel/ping'){
      return json(res,200,{ok:true,result:await aspel.pingAspel(ASPEL_ADM_URL)});
    }
    if(req.method==='POST'&&p==='/api/admin/aspel/test-login'){
      try{return json(res,200,{ok:true,result:await aspel.testLogin(DATA_DIR,ASPEL_ADM_URL)})}catch(e){console.error('ASPEL_TEST_LOGIN_ERROR',e);return json(res,500,{error:e.message})}
    }
    if(req.method==='POST'&&p==='/api/admin/aspel/session'){
      try{return json(res,200,{ok:true,result:await aspel.ensureSession(DATA_DIR,ASPEL_ADM_URL),session:aspel.sessionStatus(DATA_DIR)})}catch(e){return json(res,500,{error:e.message})}
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

  if(p.startsWith('/api/aspel/')){
    if(!device(req))return json(res,401,{error:'DEVICE_UNAUTHORIZED'});
    rememberDevice(req,res);
    if(req.method==='GET'&&p==='/api/aspel/session')return json(res,200,{ok:true,session:aspel.sessionStatus(DATA_DIR)});
    if(req.method==='POST'&&p==='/api/aspel/session/ensure'){try{return json(res,200,{ok:true,result:await aspel.ensureSession(DATA_DIR,ASPEL_ADM_URL),session:aspel.sessionStatus(DATA_DIR)})}catch(e){return json(res,500,{error:e.message})}}
    if(req.method==='POST'&&p==='/api/aspel/clients/sync'){try{return json(res,200,{ok:true,result:await aspel.fetchClients(DATA_DIR,ASPEL_ADM_URL)})}catch(e){console.error('ASPEL_CLIENT_SYNC',e);return json(res,500,{error:e.message})}}
    return json(res,404,{error:'ASPEL_ROUTE_NOT_FOUND'});
  }

  if(p.startsWith('/api/invoices')){
    if(!device(req))return json(res,401,{error:'DEVICE_UNAUTHORIZED'});
    rememberDevice(req,res);
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
  const g=aspel.startSessionGuardian(DATA_DIR,ASPEL_ADM_URL);
  console.log(`Aspel Session Guardian activo cada ${Math.round(g.intervalMs/60000)} min.`);
});

