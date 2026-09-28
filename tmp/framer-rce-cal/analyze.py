import re, struct, pathlib, subprocess, os, json, sys
root=pathlib.Path(__file__).resolve().parent
mov=root/"sameinv.mov"
raw=root/"tiff.raw"
log=root/"trace.log"
b64=(root/"sameinv.b64").read_text().strip()
import base64
mov.write_bytes(base64.b64decode(b64))

def run(cmd, **kw):
    print("+", " ".join(map(str,cmd)), flush=True)
    return subprocess.run(cmd, text=True, **kw)

print("=== ffprobe streams ===")
run(["ffprobe","-v","error","-show_entries","stream=index,codec_name,width,height,pix_fmt","-of","json",str(mov)])

env=os.environ.copy()
env["LD_PRELOAD"]=str(root/"hook.so")
with open(log,"w") as lf:
    p=subprocess.run(["ffmpeg","-v","error","-threads","1","-i",str(mov),"-map","0:v:1","-frames:v","1","-f","rawvideo","-pix_fmt","gray",str(raw),"-y"],
                     env=env,stdout=subprocess.DEVNULL,stderr=lf,text=False)
print("ffmpeg_rc",p.returncode)
data=raw.read_bytes() if raw.exists() else b""
print("raw_len",len(data))
print("raw_hex",data[:640].hex())

ptrs=[]
for off in range(0,len(data)-7,8):
    q=struct.unpack_from("<Q",data,off)[0]
    if 0x0000700000000000 <= q <= 0x00007fffffffffff:
        ptrs.append((off,q))
print("canonical_qwords",[(o,hex(q)) for o,q in ptrs])

lines=log.read_text(errors="replace").splitlines()
recs=[]
rx=re.compile(r"^CAL (\S+) a=(\S+) b=(\S+) c=(\S+) n=(\d+) d=(\S+) e=(\S+)")
for line in lines:
    m=rx.match(line)
    if m:
        tag,a,b,c,n,d,e=m.groups()
        def pv(x):
            if x=="(nil)": return 0
            try:return int(x,16)
            except:return 0
        recs.append(dict(tag=tag,a=pv(a),b=pv(b),c=pv(c),n=int(n),d=pv(d),e=pv(e),line=line))

for off,q in ptrs:
    near=[]
    for r in recs:
        for k in ("a","b","c","d","e"):
            v=r[k]
            if v and abs(v-q)<=0x200:
                near.append((abs(v-q),k,r["line"]))
    near.sort()
    print("PTR",off,hex(q),"near",near[:20])

print("=== selected allocation records ===")
for r in recs:
    if r["tag"] in {"pool_get","buf_create","buf_alloc","buf_allocz","buf_unref"}:
        print(r["line"])
