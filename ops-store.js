'use strict';
const fs = require('fs');
const path = require('path');
const {readEncrypted, writeEncrypted} = require('./crypto-store');
const ZONE = 'America/Monterrey';
const LABEL = 'a2b-operations';
const MAX = 3000;
const policyDefaults = Object.freeze({start:'', end:'', days:[1,2,3,4,5,6], preparationTime:'06:00'});
function file(dir) {return path.join(dir,'operations.enc');}
function localTime(now=new Date()) {
  const parts = new Intl.DateTimeFormat('en-US',{timeZone:ZONE,year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',hourCycle:'h23'}).formatToParts(now);
  const o={}; for(const p of parts) if(p.type!=='literal')o[p.type]=p.value;
  return {date:o.year+'-'+o.month+'-'+o.day,time:o.hour+':'+o.minute};
}
function load(dir) {
  const st=readEncrypted(file(dir),LABEL);
  if(!st)return {services:{},manifests:{},policy:{...policyDefaults}};
  return {services:st.services||{},manifests:st.manifests||{},policy:{...policyDefaults,...st.policy}};
}
function persist(dir,st) {writeEncrypted(file(dir),st,LABEL);}
function trimmed(v,n=200) {return String(v==null?'':v).trim().slice(0,n);}
function validDate(s) {return /^\d{4}-\d{2}-\d{2}$/.test(s) && !Number.isNaN(new Date(s+'T12:00:00Z').getTime());}
function cleanService(src) {
  return {
    id:trimmed(src.id,120), date:trimmed(src.date,10),time:trimmed(src.time,5),
    clientName:trimmed(src.clientName,160),address:trimmed(src.address,350),
    technicianName:trimmed(src.technicianName,160),serviceType:trimmed(src.serviceType,160),
    status:trimmed(src.status,32),productApplied:trimmed(src.productApplied,160),
    areasTreated:trimmed(src.areasTreated,300),pestsTreated:trimmed(src.pestsTreated,240),
    dose:trimmed(src.dose,100),cofeprisReg:trimmed(src.cofeprisReg,100)
  };
}
function ensureDaily(dir, force=false) {
  const clock=localTime();
  if(!force && clock.time < '06:00') return null;
  const st=load(dir),date=clock.date,existing=st.manifests[date];
  const services=Object.entries(st.services).filter(([,s])=>s.date===date)
    .map(([key,s])=>({key,...s})).sort((a,b)=>(a.time||'99:99').localeCompare(b.time||'99:99')||a.id.localeCompare(b.id));
  const signature=JSON.stringify(services);
  if(!existing || existing.signature!==signature) {
    st.manifests[date]={date,generatedAt:new Date().toISOString(),signature,services};
    for(const d of Object.keys(st.manifests))if(d<new Date(Date.now()-90*864e5).toISOString().slice(0,10))delete st.manifests[d];
    persist(dir,st);
  }
  return st.manifests[date];
}
function sync(dir,body) {
  if(!body || !Array.isArray(body.services) || body.services.length>MAX)throw Error('SERVICES_INVALID');
  const origin=trimmed(body.origin,100);
  if(!/^[a-zA-Z0-9_-]{8,100}$/.test(origin))throw Error('ORIGIN_INVALID');
  const st=load(dir);
  let changed=0;
  for(const raw of body.services) {
    if(!raw || typeof raw!=='object')continue;
    const s=cleanService(raw);if(!s.id||!validDate(s.date))continue;
    const key=origin+':'+s.id;
    if(JSON.stringify(st.services[key])!==JSON.stringify(s)){st.services[key]=s;changed++;}
  }
  if(changed)persist(dir,st);
  ensureDaily(dir);
  return {ok:true,received:body.services.length,changed};
}
function daily(dir,date) {
  if(!validDate(date))throw Error('DATE_INVALID');
  const st=load(dir), now=localTime();
  if(date===now.date && now.time>='06:00') {
    const updated=ensureDaily(dir);
    return {ok:true,scheduledFor:date,prepared:!!updated,generatedAt:updated&&updated.generatedAt,services:updated?updated.services:[]};
  }
  const existing=st.manifests[date];
  return {ok:true,scheduledFor:date,prepared:!!existing,generatedAt:existing&&existing.generatedAt,services:existing?existing.services:[]};
}
function settings(dir) {return {ok:true,policy:load(dir).policy,zone:ZONE};}
function setSettings(dir,input) {
  const st=load(dir),start=trimmed(input.start,5),end=trimmed(input.end,5);
  const time=/^([01]\d|2[0-3]):[0-5]\d$/;
  if((start&&!time.test(start))||(end&&!time.test(end))||(start&&end&&start>=end))throw Error('HOURS_INVALID');
  const days=Array.isArray(input.days)?[...new Set(input.days.map(Number))].filter(n=>Number.isInteger(n)&&n>=0&&n<=6):st.policy.days;
  if(!days.length)throw Error('DAYS_INVALID');
  st.policy={start,end,days,preparationTime:'06:00'};
  persist(dir,st);return {ok:true,policy:st.policy};
}
function start(dir) {
  const task=()=>{try{ensureDaily(dir);}catch(e){console.warn('A2B_OPERATIONS_SCHEDULER',e.message);}};
  task();const timer=setInterval(task,60000);timer.unref?.();
}
module.exports={sync,daily,settings,setSettings,start,localTime,ensureDaily};
