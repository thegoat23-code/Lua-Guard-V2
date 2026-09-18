import express from "express";
import path from "path";
import dns from "dns/promises";
import net from "net";
import {fileURLToPath} from "url";
const app=express(),dir=path.dirname(fileURLToPath(import.meta.url));
app.use(express.json({limit:"1mb"})); app.use(express.static(path.join(dir,"public")));
const MAX_DEPTH=3,MAX_BYTES=700000, httpGet=/game\s*:\s*HttpGet\s*\(\s*["'](https?:\/\/[^"' ]+)["']/ig;
const getUrls=s=>[...s.matchAll(httpGet)].map(m=>m[1]);
function privateIP(ip){if(net.isIP(ip)===4){let a=ip.split(".").map(Number);return a[0]===10||a[0]===127||a[0]===0||(a[0]===169&&a[1]===254)||(a[0]===172&&a[1]>=16&&a[1]<=31)||(a[0]===192&&a[1]===168)}return ip==="::1"||/^(fc|fd|fe80:)/i.test(ip)}
async function checkedURL(raw){let u=new URL(raw);if(!/^https?:$/.test(u.protocol))throw Error("unsupported protocol");let a=await dns.lookup(u.hostname,{all:true});if(!a.length||a.some(x=>privateIP(x.address)))throw Error("private/local destination blocked");return u}
async function fetchText(raw){let u=await checkedURL(raw);for(let i=0;i<4;i++){let r=await fetch(u,{redirect:"manual",headers:{"User-Agent":"LuaGuard/2.0"}});if(r.status>=300&&r.status<400&&r.headers.get("location")){u=await checkedURL(new URL(r.headers.get("location"),u).href);continue}if(!r.ok)throw Error("HTTP "+r.status);let n=Number(r.headers.get("content-length")||0);if(n>MAX_BYTES)throw Error("remote source too large");let t=await r.text();if(t.length>MAX_BYTES)throw Error("remote source too large");return{text:t,url:u.href}}throw Error("too many redirects")}
function scan(s,source){let f=[],add=(name,severity,explanation,re)=>{if(re.test(s))f.push({name,severity,explanation,source})};
add("Discord webhook",2,"Webhook found. Review what data is being sent.",/(discord(?:app)?\.com\/api\/webhooks|discord\.com\/api\/webhooks)/i);
add("External POST/request",1,"Can send data to an external service.",/\b(HttpPost|request|http_request|syn\.request)\b/i);
add("Roblox session/cookie targeting",5,"References Roblox session-cookie material.",/(\.ROBLOSECURITY|ROBLOSECURITY|roblox.*cookie|cookie.*roblox)/i);
add("Credential/token targeting",4,"References credentials, passwords, authorization, or auth tokens.",/(authorization|credential|password|auth[_ -]?token|access[_ -]?token)/i);
add("Sensitive local file access",3,"Reads local files; higher risk when paired with outbound requests.",/\b(readfile|listfiles)\s*\(/i);
add("Clipboard access",1,"Accesses the clipboard; not malicious by itself.",/\b(getclipboard|setclipboard|toclipboard)\s*\(/i);
add("Encoded/hidden strings",1,"String reconstruction/encoding can make review harder.",/(string\.char\s*\(|\\x[0-9a-f]{2}|bit32\.bxor|base64)/i);
let n=new Set(f.map(x=>x.name));
if((n.has("Roblox session/cookie targeting")||n.has("Credential/token targeting"))&&(n.has("External POST/request")||n.has("Discord webhook")))f.push({name:"Possible credential exfiltration chain",severity:5,explanation:"Account-related data and outbound transmission behavior appear together.",source});
if(n.has("Sensitive local file access")&&(n.has("External POST/request")||n.has("Discord webhook")))f.push({name:"Possible local-data exfiltration chain",severity:4,explanation:"Local file access and outbound transmission behavior appear together.",source});
return f}
async function analyze(code){let findings=scan(code,"Submitted script"),remote=[],seen=new Set();
async function walk(src,depth){if(depth>=MAX_DEPTH)return;for(let raw of getUrls(src)){if(seen.has(raw))continue;seen.add(raw);try{let g=await fetchText(raw),cf=scan(g.text,g.url);findings.push(...cf);remote.push({url:g.url,status:"inspected",findings:cf.length});await walk(g.text,depth+1)}catch(e){remote.push({url:raw,status:"unverified",error:e.message})}}}await walk(code,0);
let meaningful=findings.filter(x=>x.severity>0),score=meaningful.reduce((a,x)=>a+x.severity,0),unverified=remote.some(x=>x.status==="unverified"),high=meaningful.some(x=>x.severity>=5);
let status=high||score>=9?"red":meaningful.length||unverified?"yellow":"green";
let summary=status==="red"?"High-risk account-theft or data-exfiltration indicators were detected.":status==="yellow"?(unverified?"Some remote code could not be verified, or suspicious behavior needs review.":"Suspicious behavior needs review; no strong account-theft chain was confirmed."):"No account-stealing or exfiltration indicators were detected in the code LuaGuard could inspect.";
return{status,score,summary,findings,remote}}
app.post("/api/analyze",async(req,res)=>{let code=typeof req.body?.code==="string"?req.body.code:"";if(!code.trim())return res.status(400).json({error:"Paste a Lua script first."});try{res.json(await analyze(code))}catch(e){res.status(500).json({error:"Analysis failed safely: "+e.message})}});
app.listen(process.env.PORT||3000,()=>console.log("LuaGuard v2 listening"));