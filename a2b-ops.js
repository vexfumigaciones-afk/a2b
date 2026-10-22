(function(){
'use strict';
const MM=2.5;
const el=id=>document.getElementById(id);
const clean=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const certFields=[
 ['folioVal','Folio',177.86,32.59,10.2],
 ['vName','Cliente',78.85,116.69,9.2],
 ['vAddress','Domicilio',78.85,127.79,9],
 ['vService','Servicio',78.85,138.59,9.2],
 ['vAreas','Áreas tratadas',78.85,149.59,9],
 ['vPests','Plagas',78.85,160.59,9],
 ['vProduct','Producto',78.85,171.59,8.8],
 ['vDose','Dosis',78.85,182.59,9],
 ['vReg','Registro COFEPRIS',78.85,193.70,8],
 ['vValidity','Vigencia',78.85,204.80,9.2],
 ['vLicense','Licencia sanitaria',78.85,215.90,9.2]
];
const orderFields=[
 ['docBrand','Marca VEX',0,0,34],
 ['docMeta','Folio y fecha',0,0,12],
 ['docTitle','Nombre del cliente',0,0,22],
 ['docAddress','Domicilio',0,0,12],
 ['docTech','Técnico y servicio',0,0,12]
];
let kind='certificate',selected='vName',drag=null,syncTimer=null,policy={start:'',end:'',days:[0,1,2,3,4,5,6]};
function config(){
 db.settings.documentLayouts=db.settings.documentLayouts||{certificate:{},order:{}};
 db.settings.technicianPhotos=db.settings.technicianPhotos||{};
 return db.settings.documentLayouts;
}
function fields(){return kind==='certificate'?certFields:orderFields;}
function choice(f){
 const store=config()[kind],v=store[f[0]]||{};
 return {x:Number.isFinite(+v.x)?+v.x:f[2],y:Number.isFinite(+v.y)?+v.y:f[3],size:Number.isFinite(+v.size)&&+v.size>0?+v.size:f[4],color:/^#[a-f0-9]{6}$/i.test(v.color||'')?v.color:'#171717'};
}
function setField(name,patch){
 const o=config()[kind],found=fields().find(f=>f[0]===name);if(!found)return;
 o[name]={...choice(found),...patch};save();drawPreview();
}
function defaultValue(name){
 const values={folioVal:'VEX-CERT-1049',vName:'NOMBRE DEL CLIENTE',vAddress:'DOMICILIO DEL SERVICIO',
 vService:'CONTROL DE PLAGAS',vAreas:'COCINA, ALMACÉN',vPests:'CUCARACHAS',vProduct:'PRODUCTO REGISTRADO',
 vDose:'DOSIS AUTORIZADA',vReg:'REGISTRO SANITARIO',vValidity:'30 DÍAS',vLicense:db.settings.licenseNumber||'LICENCIA',
 docBrand:'VEX',docMeta:'ORDEN DE SERVICIO',docTitle:'NOMBRE DEL CLIENTE',docAddress:'Domicilio del servicio',
 docTech:'Técnico / servicio'};
 return values[name]||name;
}
function drawPreview(){
 const p=el('a2b-editor-preview');if(!p)return;
 p.innerHTML='';
 const rows=fields();
 p.className='a2b-editor-preview '+(kind==='certificate'?'is-cert':'is-order');
 if(kind==='certificate'&&typeof CERT_TEMPLATE!=='undefined')p.style.backgroundImage='url("'+CERT_TEMPLATE+'")';else p.style.backgroundImage='none';
 rows.forEach(f=>{
  const c=choice(f),node=document.createElement('div');node.className='a2b-editor-item'+(f[0]===selected?' selected':'');
  node.dataset.key=f[0];node.textContent=defaultValue(f[0]);
  if(kind==='certificate'){
    node.style.left=(c.x*MM)+'px';node.style.top=(c.y*MM)+'px';
    node.style.fontSize=Math.max(8,c.size*1.04)+'px';
  }else{
    const ix=rows.indexOf(f);node.style.left=(16+c.x*MM)+'px';node.style.top=(22+ix*50+c.y*MM)+'px';
    node.style.fontSize=Math.max(10,c.size*.8)+'px';
  }
  node.style.color=c.color;
  node.addEventListener('pointerdown',e=>{
    selected=f[0];drag={id:f[0],x:e.clientX,y:e.clientY,baseX:c.x,baseY:c.y,node};
    node.setPointerCapture(e.pointerId);node.classList.add('selected');
    const sel=el('a2b-field-select');if(sel)sel.value=selected;renderEditorInputs();
    e.preventDefault();
  });
  node.addEventListener('pointermove',e=>{
    if(!drag||drag.node!==node)return;
    const dx=(e.clientX-drag.x)/MM,dy=(e.clientY-drag.y)/MM;
    const maxX=kind==='certificate'?205:60,maxY=kind==='certificate'?268:60;
    const x=Math.max(0,Math.min(maxX,drag.baseX+dx)),y=Math.max(0,Math.min(maxY,drag.baseY+dy));
    if(kind==='certificate'){node.style.left=(x*MM)+'px';node.style.top=(y*MM)+'px';}
    else{node.style.left=(16+x*MM)+'px';node.style.top=(22+rows.indexOf(f)*50+y*MM)+'px';}
    node.dataset.x=x.toFixed(2);node.dataset.y=y.toFixed(2);
  });
  node.addEventListener('pointerup',()=>{
    if(!drag||drag.node!==node)return;
    const x=Number(node.dataset.x||c.x),y=Number(node.dataset.y||c.y);
    drag=null;setField(f[0],{x,y});renderEditorInputs();
  });
  node.addEventListener('pointercancel',()=>{drag=null;drawPreview();});
  p.appendChild(node);
 });
}
function renderEditorInputs(){
 const f=fields().find(row=>row[0]===selected);if(!f)return;const c=choice(f);
 el('a2b-x').value=c.x;el('a2b-y').value=c.y;el('a2b-font').value=c.size;el('a2b-color').value=c.color;
}
function changeKind(next){
 kind=next;selected=fields()[0][0];const s=el('a2b-field-select');
 s.innerHTML=fields().map(f=>'<option value="'+f[0]+'">'+clean(f[1])+'</option>').join('');
 s.value=selected;drawPreview();renderEditorInputs();
}
function applyDocument(kindName){
 const area=el('printArea');if(!area)return;const layouts=config()[kindName]||{};
 if(kindName==='certificate'){
  for(const f of certFields){
   const node=area.querySelector('.'+f[0]);if(!node)continue;
   const c={...choiceFor(f),...(layouts[f[0]]||{})};
   node.style.position='absolute';node.style.left=c.x+'mm';node.style.top=c.y+'mm';
   node.style.fontSize=c.size+'pt';node.style.color=c.color;
  }
  const certId=area.dataset.certId;
  const rec=db.certificates.find(c=>c.id===certId);
  const p=rec&&db.settings.technicianPhotos&&db.settings.technicianPhotos[rec.technicianName];
  if(p&&/^data:image\/(png|jpeg|webp);base64,/.test(p)){
   const img=document.createElement('img');img.src=p;img.alt='Fotografía del técnico';
   img.style.cssText='position:absolute;left:166mm;top:227mm;width:23mm;height:25mm;object-fit:cover;border:0.35mm solid #333';
   area.querySelector('.certTemplatePage')?.appendChild(img);
  }
 }else{
  const sels={docBrand:'.docBrand',docMeta:'.docMeta',docTitle:'.doc h1',docAddress:'.doc p:nth-of-type(1)',docTech:'.doc p:nth-of-type(2)'};
  for(const f of orderFields){
   const node=area.querySelector(sels[f[0]]);if(!node)continue;const c={...choiceFor(f),...(layouts[f[0]]||{})};
   node.style.transform='translate('+c.x+'mm,'+c.y+'mm)';
   node.style.fontSize=c.size+'pt';node.style.color=c.color;
  }
 }
}
function choiceFor(f){
 const kindName=certFields.some(x=>x[0]===f[0])?'certificate':'order';
 const v=config()[kindName][f[0]]||{};
 return {x:typeof v.x==='number'?v.x:f[2],y:typeof v.y==='number'?v.y:f[3],
  size:typeof v.size==='number'?v.size:f[4],color:v.color||'#171717'};
}
function maps(address){
 const url='https://www.google.com/maps/search/?api=1&query='+encodeURIComponent(address);
 window.open(url,'_blank','noopener,noreferrer');
}
function addMapToServiceModal(sid){
 const record=db.services.find(s=>s.id===sid);if(!record)return;
 const wrapper=el('dlgBody'),btn=document.createElement('button');btn.type='button';btn.className='btn';
 btn.textContent='Abrir domicilio en Maps';btn.addEventListener('click',()=>maps(record.address));wrapper.appendChild(btn);
 if(record.status!=='CERRADO'){
   const edit=document.createElement('button');edit.className='btn';edit.type='button';edit.textContent='Editar orden programada';
   edit.addEventListener('click',()=>editService(sid));wrapper.appendChild(edit);
   const preview=document.createElement('button');preview.className='btn';preview.type='button';
   preview.textContent='Imprimir orden PROGRAMADA (sin firma)';
   preview.addEventListener('click',()=>printServiceOrder(sid));wrapper.appendChild(preview);
 }
}
function editService(sid){
 const s=db.services.find(q=>q.id===sid);if(!s||s.status==='CERRADO')return;
 const props=[['date','Fecha','date'],['time','Hora','time'],['address','Domicilio','text'],
 ['serviceType','Servicio','text'],['areasTreated','Áreas tratadas','text'],['pestsTreated','Plagas','text'],
 ['productApplied','Producto','text'],['activeIngredient','Ingrediente activo','text'],['dose','Dosis','text'],
 ['cofeprisReg','Registro COFEPRIS','text']];
 modal('Editar orden programada', '<form id="a2b-edit-service">'+props.map(p=>
  '<div class="field"><label>'+clean(p[1])+'</label><input name="'+p[0]+'" type="'+p[2]+'" value="'+clean(s[p[0]])+'"></div>'
 ).join('')+'<button class="btn primary block">Guardar cambios</button></form>');
 el('a2b-edit-service').onsubmit=e=>{
  e.preventDefault();const updated=Object.fromEntries(new FormData(e.target));
  if(!updated.date||!updated.address){alert('Fecha y domicilio obligatorios');return}
  Object.assign(s,updated);s.updatedAt=new Date().toISOString();save();dlg.close();
 };
}
function initCertificateException(){
 const f=el('certForm');if(!f||f.dataset.opsReady)return;f.dataset.opsReady='yes';
 f.insertAdjacentHTML('beforeend','<div class="field"><label>Excepción sin orden: motivo y quién autorizó (solo casos extraordinarios)</label><input name="emergencyReason" placeholder="Motivo concreto"><input name="emergencyAuthorizedBy" placeholder="Nombre de quien autoriza"></div>');
 f.addEventListener('submit',e=>{
   if(f.elements.serviceId.value)return;
   if(String(f.elements.emergencyReason.value||'').trim().length<8||!String(f.elements.emergencyAuthorizedBy.value||'').trim()){
     e.preventDefault();e.stopImmediatePropagation();
     alert('Sin orden de servicio se requiere motivo y autorización documentados.');return;
   }
 },true);
}
function decorateServiceForm(){
 const f=el('fService');if(!f||f.dataset.opsReady)return;f.dataset.opsReady='yes';
 f.addEventListener('submit',e=>{
  const d=f.elements.date.value,hh=f.elements.time.value;
  if(!d)return;const weekday=new Date(d+'T12:00:00').getDay();
  if(!policy.days.includes(weekday)||(hh&&((policy.start&&hh<policy.start)||(policy.end&&hh>policy.end)))){
   e.preventDefault();e.stopImmediatePropagation();alert('Fecha u hora fuera del horario laboral configurado.');return;
  }
 },true);
}
function renderOpsServices(list){
 const target=el('a2b-day-services');if(!target)return;
 target.innerHTML=list.length?list.map(s=>
  '<div class="a2b-ops-item"><strong>'+clean(s.clientName)+'</strong><span>'+clean(s.time||'Sin hora')+' · '+clean(s.technicianName)+'</span><span>'+clean(s.address)+'</span><button class="btn small" type="button" data-map="'+clean(s.key||s.id)+'">Maps</button></div>'
 ).join(''):'<p class="subtle">No hay órdenes de servicio en esa fecha.</p>';
 target.querySelectorAll('[data-map]').forEach(b=>b.addEventListener('click',()=>{
  const s=list.find(x=>(x.key||x.id)===b.dataset.map);if(s)maps(s.address);
 }));
}
async function loadDay(){
 const d=el('a2b-day').value;
 const note=el('a2b-day-note');
 const local=db.services.filter(s=>s.date===d);
 renderOpsServices(local);
 if(!/^https?:$/.test(location.protocol))return;
 try{
  const response=await fetch('/api/ops/daily?date='+encodeURIComponent(d));
  const out=await response.json();if(!response.ok)throw Error(out.error);
  note.textContent=out.prepared?'Cola preparada automáticamente en el servidor: '+out.services.length+' servicio(s).':'Aún sin preparar: el servidor crea la cola desde las 06:00 h de Monterrey/Durango, cuando esté activo.';
  if(out.prepared)renderOpsServices(out.services);
 }catch(e){note.textContent='Cola local visible; no se pudo consultar el servidor ('+e.message+').';}
}
function queuePrint(){
 const date=el('a2b-day').value,items=db.services.filter(s=>s.date===date);
 if(!items.length){alert('No hay servicios locales para imprimir en ese día.');return}
 const parts=items.map(s=>{
  const title=s.status==='CERRADO'?'CERRADA':'PROGRAMADA — PENDIENTE DE FIRMA';
  return '<div class="doc" style="break-after:page;page-break-after:always"><div class="docHead"><div><div class="docBrand">VEX</div><b>Control de plagas</b></div><div class="docMeta">ORDEN DE SERVICIO<br>'+clean(s.id)+'<br>'+clean(s.date)+'</div></div><h1>'+clean(s.clientName)+'</h1><p><b>Domicilio:</b> '+clean(s.address)+'</p><p><b>Hora:</b> '+clean(s.time)+' &nbsp; <b>Técnico:</b> '+clean(s.technicianName)+'</p><p><b>Servicio:</b> '+clean(s.serviceType)+'</p><p><b>Áreas:</b> '+clean(s.areasTreated)+'</p><p><b>Plagas:</b> '+clean(s.pestsTreated)+'</p><p><b>Producto:</b> '+clean(s.productApplied)+' · <b>Dosis:</b> '+clean(s.dose)+'</p><p><b>Registro COFEPRIS:</b> '+clean(s.cofeprisReg)+'</p><h3>'+clean(title)+'</h3><p>El documento programado no demuestra que se realizó el servicio.</p></div>';
 });
 const area=el('printArea');area.className='';area.innerHTML=parts.join('');
 for(const node of area.querySelectorAll('.doc')){
   const map=config().order;for(const f of orderFields){
     const sels={docBrand:'.docBrand',docMeta:'.docMeta',docTitle:'h1',docAddress:'p:nth-of-type(1)',docTech:'p:nth-of-type(2)'};
     const item=node.querySelector(sels[f[0]]);if(!item)continue;const c=map[f[0]]||{};
     item.style.transform='translate('+(c.x||0)+'mm,'+(c.y||0)+'mm)';
     item.style.color=c.color||'#171717';
   }
 }
 setTimeout(()=>window.print(),100);
}
function uploadPhoto(e){
 const file=e.target.files[0],sel=el('a2b-tech');if(!file||!sel.value)return;
 if(!/^image\//.test(file.type)||file.size>6*1024*1024){alert('Solo imágenes de hasta 6 MB');return}
 const image=new Image(),reader=new FileReader();
 reader.onload=()=>{
  image.onload=()=>{
   const canvas=document.createElement('canvas');canvas.width=256;canvas.height=256;
   const ctx=canvas.getContext('2d');const size=Math.min(image.width,image.height);
   ctx.drawImage(image,(image.width-size)/2,(image.height-size)/2,size,size,0,0,256,256);
   db.settings.technicianPhotos[sel.value]=canvas.toDataURL('image/jpeg',.7);save();el('a2b-photo-note').textContent='Fotografía guardada para '+sel.value;
  };image.src=reader.result;
 };reader.readAsDataURL(file);
}
function setupPanel(){
 const nav=el('topNav'),main=document.querySelector('main.wrap');if(!nav||!main)return;
 const b=document.createElement('button');b.dataset.view='ops';b.textContent='⚙ Operación';b.onclick=()=>{go('ops');loadDay()};nav.appendChild(b);
 const section=document.createElement('section');section.id='ops';section.className='view';
 section.innerHTML='<div class="card"><h3>A2B · Centro de operaciones</h3><p class="subtle">Servicios sincronizados, preparación de órdenes a las 06:00 hora de Durango y editor de impresión.</p><div class="row"><div class="field"><label>Hora de inicio laboral</label><input id="a2b-start" type="time"></div><div class="field"><label>Fin de jornada</label><input id="a2b-end" type="time"></div></div><div class="field"><label>Días laborales</label><div id="a2b-days" class="a2b-week"></div></div><button type="button" class="btn" id="a2b-save-hours">Guardar horario laboral (administrador)</button><p class="subtle" id="a2b-hours-note">Si no hay horarios, se permiten todas las horas.</p></div>'+
 '<div class="card"><h3>Cola diaria · 06:00</h3><label>Fecha</label><input id="a2b-day" type="date"><div class="toolbar"><button class="btn" id="a2b-load-day">Actualizar cola</button><button class="btn primary" id="a2b-print-day">Imprimir órdenes del día</button></div><p id="a2b-day-note" class="subtle"></p><div id="a2b-day-services"></div><p class="subtle">El servidor prepara la cola automáticamente al activarse después de las 06:00; la impresión física necesita una impresora autorizada o un agente de impresión local.</p></div>'+
 '<div class="card"><h3>Editor visual de documentos</h3><p class="subtle">Arrastra cada dato a su posición y personaliza tipografía y color. Las posiciones se guardan en este dispositivo sin modificar el contenido legal del documento.</p><div class="row"><label>Documento<select id="a2b-layout-kind"><option value="certificate">Certificado</option><option value="order">Orden de servicio</option></select></label><label>Campo<select id="a2b-field-select"></select></label></div><div class="a2b-controls"><label>X (mm)<input type="number" id="a2b-x" step=".1"></label><label>Y (mm)<input type="number" id="a2b-y" step=".1"></label><label>Tamaño (pt)<input type="number" id="a2b-font" min="6" max="45" step=".5"></label><label>Color<input type="color" id="a2b-color"></label></div><div class="a2b-preview-wrap"><div id="a2b-editor-preview"></div></div><button class="btn" id="a2b-reset-field">Restablecer campo</button></div>'+
 '<div class="card"><h3>Fotografía del técnico para certificado</h3><p class="subtle">Adjunta la foto autorizada del técnico. Se inserta automáticamente si el certificado utiliza su nombre.</p><select id="a2b-tech"></select><input id="a2b-photo" type="file" accept="image/*"><p id="a2b-photo-note" class="subtle"></p></div>';
 main.appendChild(section);
 const style=document.createElement('style');style.textContent='.a2b-editor-preview{width:540px;height:699px;position:relative;background-size:100% 100%;background-color:#fafafa;border:1px solid #999;flex-shrink:0}.a2b-editor-preview.is-order{height:699px;background:#fff}.a2b-preview-wrap{max-width:100%;overflow-x:auto;margin:12px 0}.a2b-editor-item{position:absolute;white-space:nowrap;cursor:move;touch-action:none;max-width:280px;overflow:hidden;border:1px dashed transparent;font-family:Arial,sans-serif}.a2b-editor-item.selected{outline:1px dashed #b41016;background:#fff9}.a2b-controls{display:grid;grid-template-columns:repeat(4,minmax(90px,1fr));gap:8px}.a2b-controls input{width:100%;box-sizing:border-box}.a2b-ops-item{display:flex;gap:9px;align-items:center;flex-wrap:wrap;padding:10px 0;border-bottom:1px solid #ddd}.a2b-ops-item span{font-size:12px}.a2b-week{display:flex;gap:9px;flex-wrap:wrap}.a2b-week label{display:flex;gap:3px;align-items:center}@media(max-width:520px){.a2b-controls{grid-template-columns:repeat(2,1fr)}}';
 document.head.appendChild(style);
 el('a2b-day').value=new Date().toLocaleDateString('en-CA',{timeZone:'America/Monterrey'});
 el('a2b-layout-kind').addEventListener('change',e=>changeKind(e.target.value));
 el('a2b-field-select').addEventListener('change',e=>{selected=e.target.value;drawPreview();renderEditorInputs()});
 for(const pair of [['a2b-x','x'],['a2b-y','y'],['a2b-font','size'],['a2b-color','color']]){
  el(pair[0]).addEventListener('change',e=>{const value=pair[1]==='color'?e.target.value:Number(e.target.value);if(value===''||Number.isNaN(value))return;setField(selected,{[pair[1]]:value});});
 }
 el('a2b-reset-field').addEventListener('click',()=>{delete config()[kind][selected];save();drawPreview();renderEditorInputs()});
 el('a2b-load-day').addEventListener('click',loadDay);el('a2b-print-day').addEventListener('click',queuePrint);
 el('a2b-save-hours').addEventListener('click',saveHours);
 el('a2b-photo').addEventListener('change',uploadPhoto);
 el('a2b-tech').innerHTML=db.techs.map(t=>'<option value="'+clean(t.name)+'">'+clean(t.name)+'</option>').join('');
 const days=['Do','Lu','Ma','Mi','Ju','Vi','Sá'];
 el('a2b-days').innerHTML=days.map((d,i)=>'<label><input type="checkbox" data-day="'+i+'" checked>'+d+'</label>').join('');
 changeKind('certificate');refreshHours();loadDay();
}
function refreshHours(){
 fetch('/api/ops/settings').then(r=>r.json().then(d=>{if(!r.ok)throw Error(d.error);return d;})).then(x=>{
  policy=x.policy;el('a2b-start').value=policy.start||'';el('a2b-end').value=policy.end||'';
  el('a2b-days').querySelectorAll('[data-day]').forEach(i=>{i.checked=policy.days.includes(Number(i.dataset.day))});
 }).catch(e=>{el('a2b-hours-note').textContent='Sin conexión con la configuración del servidor: '+e.message});
}
async function saveHours(){
 try{
  const days=[...el('a2b-days').querySelectorAll('[data-day]:checked')].map(x=>Number(x.dataset.day));
  const r=await fetch('/api/ops/settings',{method:'POST',headers:{'Content-Type':'application/json'},
   body:JSON.stringify({start:el('a2b-start').value,end:el('a2b-end').value,days})});
  const data=await r.json();if(!r.ok)throw Error(data.error);
  policy=data.policy;el('a2b-hours-note').textContent='Horario laboral guardado correctamente.';
 }catch(e){el('a2b-hours-note').textContent='Para cambiar horario entra primero a /setup como administrador: '+e.message}
}
let origin=localStorage.getItem('a2bOpsOrigin');
if(!/^[a-zA-Z0-9_-]{8,100}$/.test(origin||'')){
 const bytes=new Uint8Array(12);crypto.getRandomValues(bytes);
 origin='vex-'+Array.from(bytes,n=>n.toString(16).padStart(2,'0')).join('');
 localStorage.setItem('a2bOpsOrigin',origin);
}
function sync(){
 clearTimeout(syncTimer);syncTimer=setTimeout(async()=>{
  if(!/^https?:$/.test(location.protocol))return;
  try{
   const r=await fetch('/api/ops/sync',{method:'POST',headers:{'Content-Type':'application/json'},
   body:JSON.stringify({origin,services:db.services})});
   if(!r.ok){const x=await r.json().catch(()=>({}));throw Error(x.error||r.status)}
  }catch(e){console.warn('A2B: servicios aún no sincronizados:',e.message)}
 },900);
}
function installHooks(){
 const oldCert=window.printCert;window.printCert=function(cid){
  oldCert(cid);const area=el('printArea');area.dataset.certId=cid;applyDocument('certificate');
 };
 const oldOrder=window.printServiceOrder;window.printServiceOrder=function(sid){
  oldOrder(sid);applyDocument('order');
  const s=db.services.find(x=>x.id===sid);
  const photo=s&&db.settings.technicianPhotos[s.technicianName];
  if(photo&&/^data:image\/(png|jpeg|webp);base64,/.test(photo)){
   const img=document.createElement('img');img.src=photo;img.alt='Técnico';
   img.style.cssText='float:right;width:24mm;height:25mm;object-fit:cover;margin:3mm';
   el('printArea').querySelector('.docHead')?.appendChild(img);
  }
 };
 const oldDocs=window.serviceDocs;window.serviceDocs=function(sid){oldDocs(sid);addMapToServiceModal(sid)};
 const oldOpen=window.openService;window.openService=function(){oldOpen.apply(this,arguments);decorateServiceForm()};
 initCertificateException();
}
window.A2BOPS={sync,loadDay,applyDocument};
installHooks();setupPanel();sync();
})();