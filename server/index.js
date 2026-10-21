import 'dotenv/config';
import crypto from 'node:crypto';
import http from 'node:http';
import express from 'express';
import mongoose from 'mongoose';
import httpProxy from 'http-proxy';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { validateTarget, hostnameSlug } from './security.js';

const BASE_DOMAIN = (process.env.BASE_DOMAIN || '').toLowerCase().trim();
const PANEL_SUBDOMAIN = (process.env.PANEL_SUBDOMAIN || 'panel').toLowerCase();
const PANEL_HOST = `${PANEL_SUBDOMAIN}.${BASE_DOMAIN}`;
const PASSWORD = process.env.ADMIN_PASSWORD || '';
const SECRET = process.env.SESSION_SECRET || '';
if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(BASE_DOMAIN) || !/^[a-z][a-z0-9-]{0,30}$/.test(PANEL_SUBDOMAIN) || PASSWORD.length < 16 || SECRET.length < 32) {
  console.error('Check BASE_DOMAIN, PANEL_SUBDOMAIN, ADMIN_PASSWORD (>=16 chars), SESSION_SECRET (>=32 chars)');
  process.exit(1);
}

const endpointSchema = new mongoose.Schema({
  slug: { type: String, unique: true, required: true, immutable: true },
  host: { type: String, required: true },
  port: { type: Number, required: true },
  name: { type: String, default: '' },
  active: { type: Boolean, default: true },
  deleted: { type: Boolean, default: false }
}, { timestamps: true });
const Endpoint = mongoose.model('Endpoint', endpointSchema);
const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '16kb' }));
app.use((req, res, next) => { res.setHeader('X-Content-Type-Options','nosniff'); res.setHeader('Referrer-Policy','no-referrer'); next(); });

const loginFailures = new Map();
const hash = data => crypto.createHmac('sha256', SECRET).update(data).digest('hex');
function secureEq(a, b) { const x = Buffer.from(a); const y = Buffer.from(b); return x.length === y.length && crypto.timingSafeEqual(x,y); }
function sessionValid(req) {
  const cookie = (req.headers.cookie || '').split(';').map(x=>x.trim()).find(x=>x.startsWith('expose_session='));
  if (!cookie) return false;
  const parts = cookie.slice('expose_session='.length).split('.');
  if (parts.length !== 2 || !/^\d+$/.test(parts[0])) return false;
  const exp = Number(parts[0]);
  return exp > Date.now() && exp < Date.now() + 8*24*3600*1000 && secureEq(parts[1],hash(parts[0]));
}
function auth(req,res,next) { if (!sessionValid(req)) return res.status(401).json({error:'Unauthorized'}); next(); }
function sameOrigin(req,res,next) {
  const origin = req.get('origin');
  if (origin && origin !== `https://${PANEL_HOST}` && !(process.env.COOKIE_SECURE === 'false' && /^http:\/\/localhost(:\d+)?$/.test(origin))) return res.status(403).json({error:'Origin rejected'});
  next();
}
const publicDir = path.join(path.dirname(fileURLToPath(import.meta.url)), 'public');
const dashboard = express.Router();
dashboard.get('/health', (req,res)=>res.json({ok:mongoose.connection.readyState===1}));
dashboard.post('/api/login', sameOrigin, (req,res)=>{
  const key=req.socket.remoteAddress || 'unknown'; const prev=loginFailures.get(key)||{count:0,at:0};
  if (Date.now()-prev.at<15*60*1000 && prev.count>=10) return res.status(429).json({error:'Too many attempts. Try again in 15 minutes.'});
  const supplied=String(req.body?.password||'');
  if (!secureEq(supplied,PASSWORD)) { loginFailures.set(key,{count:prev.count+1,at:Date.now()}); return res.status(401).json({error:'Wrong password'}); }
  loginFailures.delete(key);
  const expiry=String(Date.now()+7*24*3600*1000);
  res.setHeader('Set-Cookie',`expose_session=${expiry}.${hash(expiry)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=604800${process.env.COOKIE_SECURE==='false'?'':'; Secure'}`);
  res.json({ok:true});
});
dashboard.post('/api/logout', sameOrigin, (_req,res)=>{res.setHeader('Set-Cookie','expose_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');res.json({ok:true});});
dashboard.get('/api/session', (req,res)=>res.json({authenticated:sessionValid(req),domain:BASE_DOMAIN,panel:PANEL_HOST}));
dashboard.get('/api/endpoints',auth, async (_req,res,next)=>{try {res.json(await Endpoint.find({deleted:false}).sort({createdAt:-1}).select('-__v').lean());}catch(err){next(err);}});
dashboard.post('/api/endpoints',sameOrigin,auth,async(req,res,next)=>{
  try {
    const {host,port}=validateTarget(req.body?.host,req.body?.port);
    const name=String(req.body?.name||'').trim().slice(0,64);
    for(let i=0;i<5;i++) {
      const slug='e'+crypto.randomBytes(6).toString('hex');
      try {const ep=await Endpoint.create({slug,host,port,name});return res.status(201).json(ep);}catch(err){if(err.code===11000)continue;throw err;}
    }
    res.status(503).json({error:'Could not allocate an ID'});
  }catch(err){if(/Only public|IP address|Port must|port is blocked/.test(err.message))return res.status(400).json({error:err.message});next(err);}
});
dashboard.patch('/api/endpoints/:id',sameOrigin,auth,async(req,res,next)=>{
  try {
    const ep=await Endpoint.findOne({_id:req.params.id,deleted:false});if(!ep)return res.status(404).json({error:'Not found'});
    if(typeof req.body?.active==='boolean')ep.active=req.body.active;
    if(req.body?.name!==undefined)ep.name=String(req.body.name).trim().slice(0,64);
    await ep.save();res.json(ep);
  }catch(err){next(err);}
});
dashboard.delete('/api/endpoints/:id',sameOrigin,auth,async(req,res,next)=>{
  try {const ep=await Endpoint.findOneAndUpdate({_id:req.params.id,deleted:false},{$set:{deleted:true,active:false}},{new:true});if(!ep)return res.status(404).json({error:'Not found'});res.json({ok:true});}catch(err){next(err);}
});
dashboard.use(express.static(publicDir,{index:'index.html',maxAge:0}));
dashboard.use((req,res)=>res.status(404).json({error:'Not found'}));
const proxy = httpProxy.createProxyServer({ws:true,xfwd:true,changeOrigin:true,timeout:20000,proxyTimeout:20000});
proxy.on('error', (_err, _req, res)=>{ if(res && !res.headersSent && typeof res.writeHead==='function') res.writeHead(502,{'Content-Type':'text/plain'}); if(res && !res.writableEnded)res.end('Upstream unavailable'); });
const cache = new Map();
async function findEndpoint(slug) { const c=cache.get(slug);if(c&&c.until>Date.now())return c.value;const ep=await Endpoint.findOne({slug,deleted:false,active:true}).lean();cache.set(slug,{value:ep,until:Date.now()+3000});return ep; }
// Host header is only used for an exact subdomain mapping. No caller-provided target URLs.
app.use(async(req,res,next)=>{
  const host=String(req.headers.host||'').toLowerCase().replace(/:\d+$/,'');
  if(host===PANEL_HOST || (process.env.COOKIE_SECURE==='false' && (host==='localhost'||host==='127.0.0.1')))return dashboard(req,res,next);
  const slug=hostnameSlug(host,BASE_DOMAIN);
  if(!slug||slug===PANEL_SUBDOMAIN)return res.status(404).send('Unknown hostname');
  try {const ep=await findEndpoint(slug);if(!ep)return res.status(404).send('Endpoint not found or disabled');
    // Strip cookies to prevent privileged dashboard cookie forwarding.
    delete req.headers.cookie;
    proxy.web(req,res,{target:`http://${ep.host}:${ep.port}`});
  }catch(err){next(err);}
});
app.use((err,req,res,_next)=>{console.error(err);if(!res.headersSent)res.status(500).json({error:'Server error'});});
const server=http.createServer(app);
server.on('upgrade',async(req,socket,head)=>{
  const slug=hostnameSlug(req.headers.host,BASE_DOMAIN);
  if(!slug||slug===PANEL_SUBDOMAIN){socket.destroy();return;}
  try{const ep=await findEndpoint(slug);if(!ep){socket.destroy();return;}delete req.headers.cookie;proxy.ws(req,socket,head,{target:`http://${ep.host}:${ep.port}`});}catch(_){socket.destroy();}
});
await mongoose.connect(process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/expose');
await Endpoint.init();
server.listen(Number(process.env.PORT)||8080,'0.0.0.0',()=>console.log(`Expose listening on :${process.env.PORT||8080} panel ${PANEL_HOST}`));
