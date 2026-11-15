"""Build an encrypted, read-only snapshot of the Siro Lift Log for GitHub Pages.

Usage: SIRO_USER=... SIRO_PASS=... python3 -I build_siro.py <artifact index.html> <export dir> <out file>
Encryption matches important.html: PBKDF2-SHA256(user.lower():pass, 600k) -> AES-256-GCM.
"""
import base64, glob, json, os, sys
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

src, export_dir, out = sys.argv[1:4]
user, pw = os.environ["SIRO_USER"], os.environ["SIRO_PASS"]

def load(coll):
    rows = []
    for f in sorted(glob.glob(os.path.join(export_dir, coll, "*.json"))):
        d = json.load(open(f))
        d["id"] = os.path.splitext(os.path.basename(f))[0]
        rows.append(d)
    return rows

snap = {k: load(k) for k in ("daily", "food", "sessions", "activities")}
stamp = datetime.now(timezone(timedelta(hours=4))).strftime("%-d %b %Y, %H:%M")

html = open(src, encoding="utf-8").read()
start = html.index("(async ()=>{\n  db = await")
end = html.index("})();", start) + len("})();")
boot = """
const SNAP = %s;
sessions = SNAP.sessions; acts = SNAP.activities; food = SNAP.food; daily = SNAP.daily;
canWrite = false;
// Read-only snapshot: hide logging forms, keep the dashboards.
$("t-log").hidden = true;
["quick","cAdd","aSave","bSave"].forEach(id=>{ const c=$(id).closest(".card"); if(c) c.hidden=true; });
$("banner").hidden = false;
$("banner").textContent = "Read-only snapshot from %s (Dubai time). Log new data with Claude.";
fillBody(); renderAll();
let saved=null; try{ saved=localStorage.getItem("tab"); }catch(e){}
if(!saved || saved==="t-log") $("t-body").click();
""" % (json.dumps(snap, separators=(",", ":")), stamp)
page = html[:start] + boot + html[end:]
page = page.replace("<title>Siro Lift Log</title>",
                    '<title>Siro Lift Log</title><meta name="robots" content="noindex,nofollow">', 1)

salt, iv = os.urandom(16), os.urandom(12)
iters = 600000
key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iters).derive(
    (user.strip().lower() + ":" + pw).encode())
ct = AESGCM(key).encrypt(iv, page.encode("utf-8"), None)
b = lambda x: base64.b64encode(x).decode()
D = json.dumps({"salt": b(salt), "iv": b(iv), "ct": b(ct), "iter": iters})

wrapper = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>Siro Lift Log · Sign in</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#16202A;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#16202A}
form{background:#fff;border-radius:16px;padding:36px;width:min(380px,90vw);display:flex;flex-direction:column;gap:14px;box-sizing:border-box}
h1{margin:0 0 4px;font-size:24px}p{margin:0 0 8px;color:#5B6875;font-size:14px}
label{font-size:13px;font-weight:600}input{min-height:44px;padding:0 12px;border:2px solid #CDD5DD;border-radius:10px;font-size:15px}
button{min-height:44px;border:0;border-radius:10px;background:#1D4ED8;color:#fff;font-size:15px;font-weight:600;cursor:pointer}
.err{color:#9A3412;font-size:14px;min-height:18px}a{color:#1D4ED8;font-size:14px}
</style></head><body>
<form id="f"><h1>Siro Lift Log</h1><p>Private training log. Sign in to continue.</p>
<label for="u">Username</label><input id="u" autocomplete="username" required>
<label for="p">Password</label><input id="p" type="password" autocomplete="current-password" required>
<button type="submit" id="b">Sign in</button><div class="err" id="e" role="alert"></div><a href="./">← Back to main site</a></form>
<script>
var D=__D__;
function b64(s){return Uint8Array.from(atob(s),function(c){return c.charCodeAt(0)})}
async function keyFrom(u,p){var m=await crypto.subtle.importKey('raw',new TextEncoder().encode(u.trim().toLowerCase()+':'+p),'PBKDF2',false,['deriveBits']);
 return new Uint8Array(await crypto.subtle.deriveBits({name:'PBKDF2',salt:b64(D.salt),iterations:D.iter,hash:'SHA-256'},m,256));}
async function open_(raw){var k=await crypto.subtle.importKey('raw',raw,'AES-GCM',false,['decrypt']);
 var pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:b64(D.iv)},k,b64(D.ct));
 var html=new TextDecoder().decode(pt);document.open();document.write(html);document.close();}
(async function(){try{var s=sessionStorage.getItem('siro_key');if(s){await open_(b64(s));}}catch(e){try{sessionStorage.removeItem('siro_key')}catch(_){}}})();
document.getElementById('f').addEventListener('submit',async function(ev){ev.preventDefault();var e=document.getElementById('e'),b=document.getElementById('b');
 e.textContent='';b.disabled=true;b.textContent='Checking…';
 try{var raw=await keyFrom(document.getElementById('u').value,document.getElementById('p').value);
  await open_(raw);
  try{sessionStorage.setItem('siro_key',btoa(String.fromCharCode.apply(null,raw)))}catch(_){}}
 catch(x){try{sessionStorage.removeItem('siro_key')}catch(_){};e.textContent='Wrong username or password.';b.disabled=false;b.textContent='Sign in';}});
</script></body></html>
""".replace("__D__", D)
open(out, "w", encoding="utf-8").write(wrapper)
print("wrote", out, len(wrapper), "bytes;", {k: len(v) for k, v in snap.items()})
