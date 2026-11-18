#!/usr/bin/env python3
"""Native synthetic identity/DNS/SOCKS fixture; run only in disposable netns."""
import http.server, json, os, socket, socketserver, struct, subprocess, threading, time, uuid
from pathlib import Path
ROOT=Path(os.environ['PROBE_DIR']); BIN=os.environ['MIHOMO_BIN']; GOST=os.environ['GOST_BIN']; MODE=os.environ['MODE']
events=[]; checks=[]; processes=[]
def check(name,ok,detail):
 checks.append([name,bool(ok),str(detail)]);print(('PASS ' if ok else 'FAIL ')+name+' '+str(detail),flush=True)
class U(socketserver.ThreadingUDPServer):allow_reuse_address=True;daemon_threads=True
class T(socketserver.ThreadingTCPServer):allow_reuse_address=True;daemon_threads=True
class DNS(socketserver.BaseRequestHandler):
 def handle(self):
  d,s=self.request;i=12;labels=[]
  while d[i]:n=d[i];i+=1;labels.append(d[i:i+n].decode());i+=n
  i+=1;qt=struct.unpack('!H',d[i:i+2])[0];end=i+4;host='.'.join(labels);tag=self.server.tag;events.append(('dns',tag,host,qt))
  addr={'public':'127.0.0.43','a':'127.0.0.41','b':'127.0.0.42'}[tag]
  if tag=='public' and host=='blocked.corp.test':addr='127.0.0.41'
  out=d[:2]+b'\x81\x80'+d[4:6]+(b'\x00\x01' if qt==1 else b'\x00\x00')+b'\x00\x00\x00\x00'+d[12:end]
  if qt==1:out+=b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x1e\x00\x04'+socket.inet_aton(addr)
  s.sendto(out,self.client_address)
class Echo(socketserver.BaseRequestHandler):
 def handle(self):
  d,s=self.request;events.append(('udp-target',self.server.tag));s.sendto(self.server.tag.encode(),self.client_address)
class HTTP(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  events.append(('tcp-target',self.server.tag));self.send_response(200);self.end_headers();self.wfile.write(self.server.tag.encode())
 def log_message(self,*a):pass
def serve(cls,addr,handler,tag):
 s=cls(addr,handler);s.tag=tag;threading.Thread(target=s.serve_forever,daemon=True).start()
def start(name,cmd,cfg):
 path=ROOT/(name+'.json');path.write_text(json.dumps(cfg));log=open(ROOT/(name+'.log'),'w');p=subprocess.Popen(cmd+[str(path)],stdout=log,stderr=log);processes.append((p,log));time.sleep(.6)
 if p.poll()!=None:raise RuntimeError(name+' died '+(ROOT/(name+'.log')).read_text())
def recvn(s,n):
 b=b''
 while len(b)<n:
  x=s.recv(n-len(b))
  if not x:raise EOFError()
  b+=x
 return b
def send(uid,proto,host='same.corp.test'):
 s=socket.create_connection(('127.0.0.1',19151),timeout=4);s.settimeout(4);h=host.encode();port=12345 if proto=='udp' else 18080
 head=b'\x00'+uuid.UUID(uid).bytes+b'\x00'+(b'\x02' if proto=='udp' else b'\x01')+struct.pack('!H',port)+b'\x02'+bytes([len(h)])+h
 s.sendall(head+(b'\x00\x05probe' if proto=='udp' else b'GET / HTTP/1.0\r\nHost: test\r\n\r\n'))
 try:
  recvn(s,2)
  if proto=='udp':n=struct.unpack('!H',recvn(s,2))[0];return recvn(s,n).decode()
  data=b''
  while x:=s.recv(4096):data+=x
  return data.split(b'\r\n\r\n',1)[1].decode()
 finally:s.close()
try:
 for tag,ns,target in [('public','127.0.0.10','127.0.0.43'),('a','127.0.0.11','127.0.0.41')]:
  if not (tag=='a' and os.environ.get('DNS_DOWN_A')=='1'):serve(U,(ns,53),DNS,tag)
  serve(U,(target,12345),Echo,tag);serve(T,(target,18080),HTTP,tag)
 for tag,ip,dns in [('a','127.0.0.31','127.0.0.11')]:
  cfg={'services':[{'name':tag,'addr':ip+':19090','handler':{'type':'socks5','metadata':{'udp':True}},'listener':{'type':'tcp'},'resolver':tag}],'resolvers':[{'name':tag,'nameservers':[{'addr':'udp://'+dns+':53','prefer':'ipv4'}]}]}
  start('gost-'+tag,[GOST,'-C'],cfg)
 ids={x:str(uuid.uuid4()) for x in ('ordinary','a')}
 proxies=[]
 for tag,ip,dns in [('a','127.0.0.31','127.0.0.11')]:
  v={'name':tag,'type':'socks5','server':ip,'port':19090,'udp':True}
  if MODE=='patched':v['resolver-dns']=['127.0.0.13',dns]
  proxies.append(v)
 rules=['AND,((IN-USER,ordinary),(IP-CIDR,127.0.0.41/32)),REJECT','AND,((IN-USER,a),(DOMAIN-SUFFIX,corp.test)),a','MATCH,DIRECT']
 if os.environ.get('CORP_IP_GUARD')=='1':rules.insert(1,'AND,((IN-USER,a),(IP-CIDR,10.0.0.0/8)),a')
 if os.environ.get('CORP_IP_GUARD')=='2':rules.insert(1,'AND,((IN-USER,a),(IP-CIDR,10.0.0.0/8,no-resolve)),a')
 cfg={'log-level':'debug','dns':{'enable':True,'ipv6':False,'nameserver':['127.0.0.10:53']},'proxies':proxies,'listeners':[{'name':'v','type':'vless','listen':'127.0.0.1','port':19151,'allow-insecure':True,'users':[{'username':n,'uuid':v} for n,v in ids.items()]}],'rules':rules}
 start('mihomo',[BIN,'-d',str(ROOT/'work'),'-f'],cfg)
 if os.environ.get('DNS_DOWN_A')=='1':
  for proto in ['tcp','udp']:
   before=len(events)
   try:result=send(ids['a'],proto,'down-a.corp.test')
   except Exception as e:result='ERROR '+str(e)
   ev=events[before:]
   check(MODE+' '+proto+' corp DNS unavailable no fallback',result.startswith('ERROR') and not any(x[0]=='dns' and x[1] in ('public',) for x in ev) and not any(x[0].endswith('-target') for x in ev),(result,ev))
  for n in ['ordinary']:
   before=len(events)
   try:result=send(ids[n],'udp','live.corp.test')
   except Exception as e:result='ERROR '+str(e)
   check(MODE+' positive other identity '+n,result=='public',(result,events[before:]))
  (ROOT/('results-'+MODE+'-dns-down.json')).write_text(json.dumps(checks,indent=2));raise SystemExit(1 if any(not c[1] for c in checks) else 0)
 for proto in (['udp','tcp'] if os.environ.get('UDP_FIRST')=='1' else ['tcp','udp']):
  for n in ['a','ordinary','ordinary','a']:
   before=len(events)
   try:result=send(ids[n],proto)
   except Exception as e:result='ERROR '+str(e)
   suffix=events[before:]; expected={'a':'a','ordinary':'public'}[n]
   dns_public=any(x[:2]==('dns','public') for x in suffix);dns_corp=any(x[0]=='dns' and x[1] in ('a',) for x in suffix)
   check(MODE+' '+proto+' '+n,result==expected and (not dns_public if n!='ordinary' else not dns_corp),(result,suffix))
 for proto in ['tcp','udp']:
  before=len(events)
  try:result=send(ids['ordinary'],proto,'blocked.corp.test')
  except Exception as e:result='ERROR '+str(e)
  check(MODE+' '+proto+' ordinary private answer blocked',result.startswith('ERROR') and not any(x[0].endswith('-target') and x[1]=='a' for x in events[before:]),(result,events[before:]))
 (ROOT/('results-'+MODE+'.json')).write_text(json.dumps(checks,indent=2))
finally:
 for p,f in processes:p.terminate()
 for p,f in processes:
  try:p.wait(timeout=3)
  except subprocess.TimeoutExpired:p.kill();p.wait()
  f.close()
if any(not c[1] for c in checks):raise SystemExit(1)
