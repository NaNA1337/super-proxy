#!/usr/bin/env python3
"""Exercise real processes. No VPN provider or public internet is simulated as working."""
import base64
import hashlib
import http.cookiejar
import io
import http.server
import threading
import json
import os
from pathlib import Path
import re
import secrets
import signal
import ssl
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile

binary, manager, initializer = sys.argv[1:]
ctx = ssl._create_unverified_context()  # localhost fixture; Manager pins the certificate below
cookies = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies), urllib.request.HTTPSHandler(context=ctx), urllib.request.ProxyHandler({}))
csrf = ''

def request(url, data=None, headers=None, expected=200):
    h = dict(headers or {})
    if data is not None:
        h.update({'Content-Type': 'application/json', 'X-CSRF-Token': csrf})
    req = urllib.request.Request(url, data=json.dumps(data).encode() if data is not None else None, headers=h)
    try:
        resp = opener.open(req, timeout=12)
    except urllib.error.HTTPError as e:
        resp = e
    body = resp.read()
    assert resp.code == expected, (url.split('?')[0], resp.code, body[:200])
    return json.loads(body) if 'application/json' in resp.headers.get('Content-Type', '') else body

with tempfile.TemporaryDirectory(prefix='sp-linked-') as temp:
    root = Path(temp)
    cfg = root / 'config.yaml'
    subprocess.run([initializer, '-address', 'proxy.example.com', '-output', str(cfg)], check=True)
    original = cfg.read_text()
    token = re.search(r"key: ([0-9a-f]{64})", original).group(1)
    class SlowDiscovery(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            time.sleep(30)
            self.send_response(503)
            self.end_headers()
        def log_message(self,*args): pass
    source=http.server.ThreadingHTTPServer(('127.0.0.1',0),SlowDiscovery)
    threading.Thread(target=source.serve_forever,daemon=True).start()
    cfg.write_text(original.replace('https://www.vpngate.net/api/iphone/', f'http://127.0.0.1:{source.server_port}'))
    assert cfg.stat().st_mode & 0o777 == 0o600
    duplicate = subprocess.run([initializer, '-address', 'proxy.example.com', '-output', str(cfg)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    assert duplicate.returncode != 0, 'initializer overwrote existing credentials'
    processes = []
    logs = []
    try:
        for name, argv, env in [
            ('daemon', [binary, str(cfg)], {}),
            ('manager', [os.environ.get('LINKED_MANAGER_BINARY', str(Path(manager)/'bin/super-proxy-web')), '-host', '127.0.0.1', '-port', '18443', '-data-dir', str(root/'manager')], {'ALLOW_PRIVATE_HOSTS':'true'}),
        ]:
            log = open(root/f'{name}.log', 'w+')
            logs.append(log)
            processes.append(subprocess.Popen(argv, cwd=root, env={**os.environ, **env}, stdout=log, stderr=log, start_new_session=True))
        agent = 'https://127.0.0.1:60000'
        web = 'http://127.0.0.1:18443'
        auth = {'Authorization': f'Bearer {token}'}
        ready_started=time.monotonic()
        for _ in range(150):
            try:
                request(agent+'/api/v1/status', headers=auth)
                request(web+'/api/auth/bootstrap-status')
                break
            except (OSError, AssertionError):
                time.sleep(.1)
        else:
            raise AssertionError('processes did not become ready')
        assert time.monotonic()-ready_started < 15, 'slow discovery delayed management startup'
        print('PASS: management starts while discovery HTTP response is stalled',flush=True)
        password = re.search(r'Temporary password:\s*([^\r\n]+)', (root/'manager.log').read_text()).group(1).strip()
        login = request(web+'/api/auth/login', {'username':'admin', 'password':password})
        csrf = login['csrf_token']
        password2 = secrets.token_hex(20)+'Aa1!'
        change = request(web+'/api/auth/change-password', {'current_password':password,'new_password':password2,'confirm_password':password2})
        csrf = change.get('csrf_token',csrf)
        print('PASS: real Manager bootstrap, login, mandatory password change', flush=True)
        cert = ssl.get_server_certificate(('127.0.0.1',60000))
        fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert)).hexdigest()
        host = request(web+'/api/hosts', {'name':'Real gateway','address':'proxy.example.com','agent_url':agent,'token':token,'tls_fingerprint':fingerprint,'is_default':True}, expected=201)
        hostid = host['id']
        probe = request(web+f'/api/hosts/{hostid}/test', {})
        assert probe['success'], probe
        request(agent+'/api/v1/status', expected=401)
        request(agent+'/api/v1/status', headers={'Authorization':'Bearer wrong'}, expected=403)
        for name in ['status','system','current-exits','slots','pool','pool/qualified','nodes','routing','metrics']:
            request(web+'/api/daemon/'+name, headers={'X-Host-ID':hostid})
        assert request(agent+'/api/v1/current-exits',headers=auth) == []
        routes = request(agent+'/api/v1/routing',headers=auth)
        assert [s['table_id'] for s in routes['slots']] == [100,101,102]
        print('PASS: pinned HTTPS host registration, auth failures, nine management endpoints, empty pool', flush=True)
        # A credential-free candidate exercises accepted -> pollable -> FAILED,
        # without claiming a public VPN switch succeeded.
        with sqlite3.connect(root/'manager.db') as db:
            db.execute("INSERT INTO nodes (id,ip,status,country) VALUES (?,?,?,?)", ('linked-no-credentials','198.51.100.2','QUALIFIED','JP'))
        operation = request(web+'/api/daemon/slots/0/switch', {'node_id':'linked-no-credentials'}, headers={'X-Host-ID':hostid}, expected=202)
        for _ in range(100):
            state = request(web+'/api/daemon/operations/'+operation['operation_id'], headers={'X-Host-ID':hostid})
            if state['status'] == 'FAILED':
                break
            time.sleep(.1)
        else:
            raise AssertionError('credential-free switch did not fail')
        assert state['operation_id'] == operation['operation_id']
        print('PASS: manual switch accepted, returned operation ID is pollable, missing VPN credentials fail explicitly',flush=True)
        bundle = request(agent+'/api/v1/client-config/all',headers=auth)
        proxied = request(web+f'/api/hosts/{hostid}/client-config')
        assert proxied['available'] and len(proxied['nodes']) == 1, proxied
        profiles = {p['id']:p['content'] for p in bundle['profiles']}
        assert len(profiles) == 5
        assert profiles == {p['id']:p['content'] for p in proxied['nodes'][0]['profiles']}
        assert token not in json.dumps(proxied) and 'private_key' not in json.dumps(proxied)
        xraycfg = root/'client.json'
        xraycfg.write_text(profiles['xray'])
        subprocess.run(['xray','run','-test','-c',str(xraycfg)],check=True,stdout=subprocess.DEVNULL)
        zipped = request(web+'/api/client-configs/export-zip', {'selections':[{'host_id':hostid,'node_id':bundle['node']['id']}]})
        with zipfile.ZipFile(io.BytesIO(zipped)) as z:
            exported = [z.read(n).decode() for n in z.namelist() if not n.endswith('README.txt')]
            assert all(content in exported for content in profiles.values()), z.namelist()
        sub = request(web+'/api/subscriptions', {'name':'linked-test','host_id':hostid,'profile':'all_nodes'}, expected=201)
        assert base64.b64decode(request(sub['sub_url'])).decode().strip() == profiles['vless']
        request(web+f"/api/subscriptions/{sub['subscription']['id']}/revoke", {})
        request(sub['sub_url'], expected=403)
        print('PASS: five exact canonical profiles, Xray client validation, ZIP, subscription and revocation', flush=True)
        env = {**os.environ, 'LINKED_MANAGER_URL':web, 'LINKED_PASSWORD':password2, 'LINKED_HOST_ID':hostid, 'LINKED_MANAGER_DIR':manager}
        subprocess.run(['node', str(Path(__file__).with_name('browser.mjs'))], env=env, check=True)
        processes[0].send_signal(signal.SIGTERM)
        processes[0].wait(timeout=20)
        stopped = request(web+f'/api/hosts/{hostid}/client-config')
        assert not stopped['available'] and not stopped.get('profiles') and not stopped.get('nodes'), stopped
        print('PASS: stopped daemon invalidates client configuration; no stale successful export', flush=True)
        restarted = subprocess.Popen([binary,str(cfg)],cwd='/',stdout=logs[0],stderr=logs[0],start_new_session=True)
        processes.append(restarted)
        for _ in range(100):
            try:
                again = request(agent+'/api/v1/client-config/all',headers=auth)
                break
            except (OSError,AssertionError):
                time.sleep(.1)
        else:
            raise AssertionError('restart from / failed')
        assert profiles == {p['id']:p['content'] for p in again['profiles']}, 'credentials changed after restart'
        assert ssl.get_server_certificate(('127.0.0.1',60000)) == cert, 'TLS certificate changed after restart'
        assert request(web+f'/api/hosts/{hostid}/client-config')['available']
        print('PASS: generated config is private and never overwritten; restart from / preserves TLS and all client credentials',flush=True)
        print('PASS: linked control-plane and browser checks. Public VPN/Reality reachability is not asserted.', flush=True)
    except Exception:
        # Local logs contain generated credentials; show only redacted startup errors.
        for name in ['daemon','manager']:
            content = (root/f'{name}.log').read_text()[-3000:]
            content = content.replace(token,'[REDACTED]')
            content = re.sub(r'(Temporary password:).*',r'\1 [REDACTED]',content)
            print(name+': '+content, file=sys.stderr)
        raise
    finally:
        for proc in reversed(processes):
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
        for log in logs:
            log.close()
