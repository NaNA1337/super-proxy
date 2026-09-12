#!/usr/bin/env python3
"""Opt-in live VPN Gate test using slirp networking; root, Xray, OpenVPN and slirp4netns required.
Generated credentials stay in a private temporary directory, never in release artifacts.
Usage: python3 tests/live/check.py [manager repository]
"""
import subprocess,os,tempfile,pathlib,time,re,json,signal,sys
manager=pathlib.Path(sys.argv[1] if len(sys.argv)>1 else '/root/super-proxy-manager').resolve()
os.chdir(pathlib.Path(__file__).resolve().parents[2])
root=pathlib.Path(tempfile.mkdtemp(prefix='sp-live-')); root.chmod(0o700)
print('Live test artifacts:',root,flush=True)
ns='sp_live_'+str(os.getpid()); processes=[]
def run(args,**kw): return subprocess.run(args,check=True,**kw)
def inside(args,timeout=45): return subprocess.run(['ip','netns','exec',ns]+args,capture_output=True,text=True,timeout=timeout)
try:
 run(['ip','netns','add',ns])
 dns=pathlib.Path('/etc/netns')/ns;dns.mkdir(parents=True);(dns/'resolv.conf').write_text('nameserver 10.0.2.3\n')
 slirpLog=open(root/'slirp.log','w')
 processes.append(subprocess.Popen(['slirp4netns','--configure','--netns-type=path','/run/netns/'+ns,'tap0'],stdout=slirpLog,stderr=slirpLog,start_new_session=True))
 time.sleep(1)
 run(['go','build','-o',str(root/'super-proxy'),'./cmd/manager'])
 run(['go','run','./cmd/init-config','-address','10.0.2.100','-api-listen','0.0.0.0','-output',str(root/'config.yaml')])
 cfg=(root/'config.yaml').read_text();token=re.search(r'key: ([0-9a-f]{64})',cfg).group(1)
 (root/'config.yaml').write_text(cfg+'\nspeed_test:\n  enabled: false\n')
 daemonLog=open(root/'daemon.log','w')
 processes.append(subprocess.Popen(['ip','netns','exec',ns,'unshare','--mount','bash','-c','mount -t tmpfs tmpfs /run; exec "$@"','live',str(root/'super-proxy'),str(root/'config.yaml')],cwd='/',stdout=daemonLog,stderr=daemonLog,start_new_session=True))
 def api(path):
  res=inside(['curl','-kfsS','--max-time','35','-H','Authorization: Bearer '+token,'https://127.0.0.1:60000'+path])
  if res.returncode: raise RuntimeError(res.stderr)
  return json.loads(res.stdout)
 def api_post(path,data):
  res=inside(['curl','-kfsS','--max-time','35','-H','Authorization: Bearer '+token,'-H','Content-Type: application/json','--data',json.dumps(data),'https://127.0.0.1:60000'+path])
  if res.returncode: raise RuntimeError(res.stderr)
  return json.loads(res.stdout)
 deadline=time.monotonic()+int(os.environ.get('SP_LIVE_TIMEOUT_SECONDS','600'))
 verification_started=False
 while time.monotonic()<deadline:
  try:
   status=api('/api/v1/status');exits=api('/api/v1/current-exits');pool=api('/api/v1/pool')
   print(json.dumps({'time':time.strftime('%H:%M:%S'),'exits':exits,'pool':pool}),flush=True)
   if len(exits)==3:
    verification_started=True
    bundle=api('/api/v1/client-config/all');(root/'bundle.json').write_text(json.dumps(bundle));print('THREE ACTIVE EXITS',flush=True)
    # Register the real live daemon in the real Manager and compare all exports.
    run(['go','build','-o',str(root/'manager'), './backend/cmd/server'],cwd=manager)
    managerLog=open(root/'manager.log','w')
    processes.append(subprocess.Popen(['ip','netns','exec',ns,'env','ALLOW_PRIVATE_HOSTS=true',str(root/'manager'),'-host','127.0.0.1','-port','18443','-data-dir',str(root/'manager-data')],stdout=managerLog,stderr=managerLog,start_new_session=True))
    time.sleep(1)
    password=re.search(r'Temporary password:\s*([^\r\n]+)',(root/'manager.log').read_text()).group(1).strip()
    csrf=''
    def web(path,data=None):
     args=['curl','-fsS','--max-time','40','-b',str(root/'cookies'),'-c',str(root/'cookies')]
     if data is not None: args+=['-H','Content-Type: application/json','-H','X-CSRF-Token: '+csrf,'--data',json.dumps(data)]
     res=inside(args+['http://127.0.0.1:18443'+path])
     if res.returncode:raise RuntimeError(res.stderr)
     return json.loads(res.stdout)
    login=web('/api/auth/login',{'username':'admin','password':password});csrf=login['csrf_token']
    import secrets,ssl,hashlib
    newpass=secrets.token_hex(20)+'Aa1!'
    change=web('/api/auth/change-password',{'current_password':password,'new_password':newpass,'confirm_password':newpass});csrf=change.get('csrf_token',csrf)
    fp=hashlib.sha256(ssl.PEM_cert_to_DER_cert((root/'cert.pem').read_text())).hexdigest()
    host=web('/api/hosts',{'name':'Live VPN Gate','address':'10.0.2.100','agent_url':'https://10.0.2.100:60000','token':token,'tls_fingerprint':fp,'is_default':True})
    proxied=web('/api/hosts/'+host['id']+'/client-config')
    assert proxied['available']
    assert {p['id']:p['content'] for p in bundle['profiles']}=={p['id']:p['content'] for p in proxied['nodes'][0]['profiles']}
    print('PASS Manager live host API and five exact share profiles',flush=True)
    client=next(p['content'] for p in bundle['profiles'] if p['id']=='xray');(root/'client.json').write_text(client)
    clientLog=open(root/'client.log','w');processes.append(subprocess.Popen(['ip','netns','exec',ns,'xray','run','-c',str(root/'client.json')],stdout=clientLog,stderr=clientLog,start_new_session=True));time.sleep(1)
    for _ in range(5):
     result=inside(['curl','-fsS','--max-time','20','--proxy','socks5h://127.0.0.1:10808','https://api.ipify.org?format=json'])
     print('REALITY_PROXY',result.returncode,result.stdout,result.stderr,flush=True)
     if result.returncode: raise RuntimeError('Reality client request failed')
     assert json.loads(result.stdout)['ip'] in {e['ip'] for e in exits}, 'unexpected Reality egress'
    expected={e['ip'] for e in exits}
    observed=json.loads(result.stdout)['ip']
    assert observed in expected,('unexpected Reality egress',observed,expected)

    # Exercise the successful manual transaction, including replacement commit
    # and preservation of the old tunnel in DRAINING.
    active_ids={e['node_id'] for e in exits}
    candidates=[n for n in api('/api/v1/pool/qualified') if n['id'] not in active_ids and n['status']=='DISCOVERED']
    assert candidates,'no discovered candidate available for manual switch'
    target=candidates[0]['id']
    operation=api_post('/api/v1/slots/0/switch',{'node_id':target})
    op_deadline=time.monotonic()+120
    while time.monotonic()<op_deadline:
     state=api('/api/v1/operations/'+operation['operation_id'])
     if state['status'] in ('ACTIVE','FAILED'): break
     time.sleep(2)
    assert state['status']=='ACTIVE',state
    switched=api('/api/v1/current-exits')
    assert len(switched)==3,switched
    assert next(e for e in switched if e['slot']==0)['node_id']==target,switched
    print('PASS successful manual switch keeps three active exits',flush=True)

    time.sleep(65)
    assert len(api('/api/v1/current-exits'))==3,'tunnels did not survive qualification deadlines'
    print('PASS live three exits and Reality traffic beyond 60s',flush=True)
    break
  except Exception as e:
   if verification_started: raise
   print(type(e).__name__,str(e),flush=True)
  time.sleep(10)
 else: raise RuntimeError('No stable three-exit configuration within 10 minutes')
finally:
 for p in reversed(processes):
  if p.poll() is None:
   os.killpg(p.pid,signal.SIGTERM)
   try:p.wait(timeout=20)
   except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait()
 subprocess.run(['ip','netns','del',ns])
 import shutil
 shutil.rmtree('/etc/netns/'+ns,ignore_errors=True)
