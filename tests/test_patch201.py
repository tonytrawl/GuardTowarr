import unittest, threading, json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
from test_monitor import m

class PatchTests(unittest.TestCase):
    def setUp(self):
        m._QBIT_SESSIONS.clear()
        self.calls=[]; self.reject=False; self.bad_login=False
        owner=self
        class API(BaseHTTPRequestHandler):
            def log_message(self,*args): pass
            def do_GET(self): self.respond()
            def do_POST(self): self.respond()
            def respond(self):
                body=self.rfile.read(int(self.headers.get('Content-Length',0)))
                owner.calls.append((self.command,self.path,dict(self.headers),body))
                login=self.path.endswith('/auth/login')
                status=200 if login or not owner.reject else 403
                self.send_response(status)
                if login: self.send_header('Set-Cookie','SID=fixture-session; HttpOnly; Path=/')
                self.end_headers(); self.wfile.write((('Fails.' if owner.bad_login else 'Ok.') if login else '[]').encode())
        self.server=ThreadingHTTPServer(('127.0.0.1',0),API)
        threading.Thread(target=self.server.serve_forever,daemon=True).start()
        self.addCleanup(self.server.server_close);self.addCleanup(self.server.shutdown)
        self.url='http://127.0.0.1:'+str(self.server.server_port)
        self.svc={'url':self.url+'/qbit','username':'fixture','password':'fixture-password','type':'qbit'}
    def test_legacy_login_and_cookie_reuse(self):
        for _ in range(3): self.assertEqual(m._qbit_request(self.svc,'torrents/info')[0],200)
        self.assertEqual(len(self.calls),4)
        for _,path,headers,_ in self.calls[1:]:
            self.assertEqual(headers['Cookie'],'SID=fixture-session')
            self.assertEqual(headers['Origin'],self.url)
            self.assertEqual(headers['Referer'],self.url+'/qbit/')
        self.assertFalse(m.missing_credentials(self.svc))
    def test_api_key_skips_login_and_credentials_optional(self):
        svc={'url':self.url,'api_key':'fixture-key','type':'qbit'}
        self.assertFalse(m.missing_credentials(svc))
        m._qbit_request(svc,'torrents/info')
        self.assertEqual(len(self.calls),1)
        self.assertEqual(self.calls[0][2]['X-Api-Key'],'fixture-key')
        self.assertNotIn('Cookie',self.calls[0][2])
    def test_bad_login_cooldown(self):
        self.bad_login=True
        for _ in range(2):
            with self.assertRaisesRegex(m.QbitRequestError,'username/password'): m._qbit_request(self.svc,'torrents/info')
        self.assertEqual(len(self.calls),1)
    def test_key_rejection_never_falls_back(self):
        self.reject=True;self.svc['api_key']='invalid'
        for _ in range(2):
            with self.assertRaisesRegex(m.QbitRequestError,'API-key'): m._qbit_request(self.svc,'torrents/info')
        self.assertEqual(len(self.calls),1)
    def test_expired_session_get_reauth_once(self):
        m._qbit_request(self.svc,'torrents/info');self.calls.clear();self.reject=True
        with self.assertRaises(m.QbitRequestError):m._qbit_request(self.svc,'torrents/info')
        self.assertEqual([c[1].split('/')[-1] for c in self.calls],['info','login','info'])
    def test_mutation_is_not_replayed(self):
        m._qbit_request(self.svc,'torrents/info');self.calls.clear();self.reject=True
        result=m._qbit_torrent_op(self.svc,'recheck',['a'*40])
        self.assertFalse(result['ok']);self.assertEqual(len(self.calls),1)
        self.assertEqual(self.calls[0][0],'POST')
    def test_parallel_requests_share_login(self):
        with m.concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(lambda _:m._qbit_request(self.svc,'torrents/info'),range(4)))
        self.assertEqual(sum(c[1].endswith('/login') for c in self.calls),1)

class ConfigPatchTests(unittest.TestCase):
    def test_shortcuts_require_explicit_remote_opt_in(self):
        cfg=m._merge_defaults({});cfg['ui']['show_shortcuts']=True
        svc=cfg['services']['radarr'];svc.update(disabled=False,url='http://private.invalid',label='Movies')
        self.assertEqual(len(m.dashboard_links(cfg)),1)
        self.assertEqual(m.dashboard_links(cfg,True),[])
        svc.update(link_remote=True);self.assertEqual(m.dashboard_links(cfg,True),[])
        svc['link_url']='https://movies.example.com'
        links=m.dashboard_links(cfg,True)
        self.assertEqual(m.public_payload({'shortcuts':links},cfg)['shortcuts'],links)
        self.assertNotIn('private.invalid',json.dumps(m.public_payload({'url':svc['url']},cfg)))
        cfg['shortcuts']=[{'label':'Private','url':'https://private.example.com'},{'label':'Shared','url':'https://shared.example.com','show_remote':True}]
        self.assertEqual(len(m.dashboard_links(cfg,True)),2)
    def test_shortcut_urls_and_host_validation(self):
        for url in ['javascript:alert(1)','https://user:password@example.com','https://example.com:99999','https://example.com\\evil']:
            self.assertEqual(m.safe_link_url(url),'')
        for host in ['*.example.com','https://example.com','example.com:8080','bad host']:
            self.assertFalse(m.valid_admin_host(host))
        self.assertTrue(m.valid_admin_host('dashboard.example.com'))
    def test_storage_off_avoids_disk_queries(self):
        cfg=m._merge_defaults({});cfg['services']['radarr']['disabled']=False;cfg['ui']['storage_mode']='off'
        with patch.object(m,'_arr_diskspace') as disks,patch.object(m,'_combined_now_playing',return_value=[]),patch.object(m,'get_torrents',return_value={}):
            m._compute_stats(cfg);disks.assert_not_called()
    def test_storage_selected_instance_only(self):
        cfg=m._merge_defaults({});cfg['services']['radarr'].update(disabled=False)
        cfg['services']['radarr_4k']={**cfg['services']['radarr'],'label':'Movies 4K'}
        cfg['ui']['storage_instances']=['radarr_4k'];cfg['ui']['storage_mode']='selected'
        with patch.object(m,'_arr_diskspace',return_value=[]) as disks,patch.object(m,'_combined_now_playing',return_value=[]),patch.object(m,'get_torrents',return_value={}):
            m._compute_stats(cfg);disks.assert_called_once_with(cfg['services']['radarr_4k'])

class HostPatchTests(unittest.TestCase):
    def test_exact_host_allowlist_and_malformed_hosts(self):
        handler=object.__new__(m.Handler)
        handler._is_public=lambda:False
        handler._deny=lambda *args:False
        cfg=m._merge_defaults({});cfg['allowed_hosts']=['dashboard.example.com']
        with patch.object(m,'get_config',return_value=cfg),patch.dict(m.os.environ,{'GUARDTOWARR_ALLOWED_HOSTS':'second.example.com'}):
            for host,expected in [('dashboard.example.com:9595',True),('DASHBOARD.EXAMPLE.COM.',True),('second.example.com',True),('evil.example.com',False),('dashboard.example.com.evil.test',False),('dashboard.example.com/path',False),('dashboard.example.com:bad',False)]:
                handler.headers={'Host':host,'X-Forwarded-Host':'dashboard.example.com'}
                self.assertEqual(handler._admin_host_ok(),expected,host)
    def test_legacy_configuration_keeps_login(self):
        cfg=m._merge_defaults({'services':{'qbittorrent':{'username':'existing-user','password':'existing-password','url':'http://localhost:8080','disabled':False}}})
        svc=cfg['services']['qbittorrent']
        self.assertEqual(svc['username'],'existing-user');self.assertEqual(svc['password'],'existing-password')
        self.assertFalse(svc.get('api_key'));self.assertFalse(m.missing_credentials(svc))


class ShortcutNamingTests(unittest.TestCase):
    def test_service_name_for_single_instance_and_labels_for_multiple(self):
        cfg=m._merge_defaults({});cfg['ui']['show_shortcuts']=True
        cfg['services']['sonarr'].update(disabled=False,label='TV')
        cfg['services']['radarr'].update(disabled=False,label='Movies')
        cfg['services']['qbittorrent'].update(disabled=False,label='Torrents')
        cfg['shortcuts']=[{'label':'My custom link','url':'https://example.com'}]
        self.assertEqual([r['label'] for r in m.dashboard_links(cfg)],['Radarr','Sonarr','qBittorrent','My custom link'])
        cfg['services']['radarr_4k']={**cfg['services']['radarr'],'label':'Movies 4K'}
        labels=[r['label'] for r in m.dashboard_links(cfg)]
        self.assertIn('Movies',labels);self.assertIn('Movies 4K',labels);self.assertIn('Sonarr',labels)
        cfg['services']['radarr_4k']['disabled']=True
        self.assertIn('Radarr',[r['label'] for r in m.dashboard_links(cfg)])

class RemoteShortcutSecurityTests(unittest.TestCase):
    def test_remote_credential_urls_rejected_and_filtered(self):
        for url in ['https://example.com/?apikey=unknown','https://example.com/#token=unknown','https://example.com/fixture-secret','https://example.com/fixture%2Dsecret']:
            cfg=m._merge_defaults({});cfg['ui']['show_shortcuts']=True
            cfg['services']['radarr'].update(disabled=False,api_key='fixture-secret',link_url=url,link_remote=True)
            self.assertEqual(m.dashboard_links(cfg,True),[],url)
            self.assertEqual(m.public_payload({'shortcut_url':url},cfg)['shortcut_url'],'')
            with self.assertRaises(ValueError):m.validate_config(cfg)
    def test_custom_remote_link_validation_and_private_links(self):
        cfg=m._merge_defaults({});cfg['ui']['show_shortcuts']=True
        cfg['shortcuts']=[{'label':'Private','url':'https://example.com/?page=1','show_remote':False}]
        m.validate_config(cfg);self.assertEqual(len(m.dashboard_links(cfg)),1)
        cfg['shortcuts'][0]['show_remote']=True
        with self.assertRaises(ValueError):m.validate_config(cfg)
        cfg['shortcuts'][0]['url']='https://example.com/requests'
        m.validate_config(cfg);self.assertEqual(len(m.dashboard_links(cfg,True)),1)

class RemoteOverrideTests(unittest.TestCase):
    def test_override_is_explicit_per_link_and_still_requires_remote_visibility(self):
        cfg=m._merge_defaults({});cfg['ui']['show_shortcuts']=True
        url='https://example.com/?token=fixture-secret'
        svc=cfg['services']['radarr'];svc.update(disabled=False,api_key='fixture-secret',link_url=url,link_remote=True)
        self.assertEqual(m.dashboard_links(cfg,True),[])
        svc['link_remote_override']=True
        m.validate_config(cfg)
        self.assertEqual(m.public_payload({'shortcuts':m.dashboard_links(cfg,True)},cfg)['shortcuts'][0]['shortcut_url'],url)
        svc['link_remote']=False;self.assertEqual(m.dashboard_links(cfg,True),[])
        cfg['shortcuts']=[{'label':'Shared','url':url,'show_remote':True,'remote_override':True}]
        m.validate_config(cfg);self.assertEqual(len(m.dashboard_links(cfg,True)),1)
        cfg['shortcuts'][0]['remote_override']='true'
        with self.assertRaises(ValueError):m.validate_config(cfg)
    def test_override_does_not_allow_unsafe_protocol_or_embedded_login(self):
        for url in ['javascript:alert(1)','https://user:password@example.com']:
            cfg=m._merge_defaults({});cfg['shortcuts']=[{'label':'Bad','url':url,'show_remote':True,'remote_override':True}]
            with self.assertRaises(ValueError):m.validate_config(cfg)


class DomainStorageModeTests(unittest.TestCase):
    def test_domain_url_normalization(self):
        cfg=m._merge_defaults({});cfg['allowed_hosts']=['https://Dashboard.Example.com:443/path','second.example.com']
        self.assertEqual(m.validate_config(cfg)['allowed_hosts'],['dashboard.example.com','second.example.com'])
        for host in ['https://*.example.com','ftp://example.com','https://user:pass@example.com','https://example.com:bad']:
            cfg['allowed_hosts']=[host]
            with self.assertRaises(ValueError):m.validate_config(cfg)
    def test_existing_storage_preferences_migrate(self):
        for ui,mode in [({},'all'),({'show_storage':False},'off'),({'storage_instances':['radarr']},'selected')]:
            self.assertEqual(m._merge_defaults({'ui':ui})['ui']['storage_mode'],mode)
    def test_empty_selected_mode_never_queries_all(self):
        cfg=m._merge_defaults({'ui':{'storage_mode':'selected','storage_instances':[]}})
        cfg['services']['radarr']['disabled']=False
        with patch.object(m,'_arr_diskspace') as disks,patch.object(m,'_combined_now_playing',return_value=[]),patch.object(m,'get_torrents',return_value={}):
            m._compute_stats(cfg);disks.assert_not_called()
        self.assertEqual(m._merge_defaults(cfg)['ui']['storage_mode'],'selected')
