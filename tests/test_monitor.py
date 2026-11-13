"""Offline regression tests. No user configuration or media services are touched."""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import socketserver
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
BOOT = tempfile.TemporaryDirectory()
os.environ['GUARDTOWARR_CONFIG_DIR'] = BOOT.name
spec = importlib.util.spec_from_file_location('guardtowarr_test', ROOT / 'monitor.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.paths = patch.multiple(m, CONFIG_FILE=self.file('config.json'), HISTORY_FILE=self.file('history.json'),
            DISMISS_FILE=self.file('dismissed.json'), OBSERVATION_FILE=self.file('observations.json'), ACTION_FILE=self.file('actions.json'))
        self.paths.start(); self.addCleanup(self.paths.stop)
        self.cfg = m._merge_defaults({})
        m.CONFIG.clear(); m.CONFIG.update(copy.deepcopy(self.cfg))
        m.STATE.clear(); m.STATE.update(services={}, last_poll=None)
        m._OBS_LAST.clear(); m._MALWARE_SCANNED.clear(); m._ACTION_RUNNING.clear()
        m._DISMISSED = None
        m._STATS_CACHE.update(ts=0, data=None)

    def file(self, name):
        return str(Path(self.temp.name)/name)

    def enable(self, app, name=None):
        name = name or app
        svc = copy.deepcopy(self.cfg['services'][app])
        svc.update(app=app, label=name, disabled=False, api_key='private-api-key', url='http://media.internal:1234', username='test-user')
        self.cfg['services'][name] = svc
        return svc

    def test_config_recovers_nested_garbage(self):
        for raw in (None, [], {'services': None}, {'services': {'radarr': None}}, {'services': {'sonarr': 'bad'}}):
            cfg=m._merge_defaults(raw)
            self.assertEqual(cfg['services']['radarr']['type'], 'arr')
        self.assertEqual(m._merge_defaults({'poll_interval':'oops'})['poll_interval'],30)

    def test_corrupt_config_preserved(self):
        Path(m.CONFIG_FILE).write_text('{broken')
        cfg=m.load_config(); m.save_config(cfg)
        backups=list(Path(self.temp.name).glob('config.json.corrupt-*'))
        self.assertEqual(backups[0].read_text(),'{broken')
        self.assertEqual(json.loads(Path(m.CONFIG_FILE).read_text())['schema_version'],2)

    def test_nested_bad_config_preserved(self):
        Path(m.CONFIG_FILE).write_text('{"services":{"radarr":null}}')
        m.load_config()
        self.assertEqual(len(list(Path(self.temp.name).glob('*.recovered-*'))),1)

    def test_completed_action_survives_audit_write_failure(self):
        self.enable('radarr')
        real_write = m.atomic_json
        writes = []
        def write(path, value):
            writes.append(path)
            if len(writes) == 2:
                raise OSError('disk full')
            return real_write(path, value)
        with patch.object(m, 'atomic_json', side_effect=write), patch.dict(m.ACTIONS, {'test_indexers': lambda *args: {'ok': True, 'message': 'Test completed.'}}):
            result = m.execute_action(self.cfg, 'radarr', 'test_indexers', {})
        self.assertTrue(result['ok'])
        self.assertIn('history could not be updated', result['message'])
        self.assertFalse(m._ACTION_RUNNING)
        self.assertEqual(json.loads(Path(m.ACTION_FILE).read_text())[0]['status'], 'pending')

    def test_atomic_write_failure_keeps_original(self):
        m.atomic_json(m.CONFIG_FILE, {'old':1})
        with patch.object(m.os,'replace',side_effect=OSError('disk problem')):
            with self.assertRaises(OSError):m.atomic_json(m.CONFIG_FILE,{'new':2})
        self.assertEqual(json.loads(Path(m.CONFIG_FILE).read_text()),{'old':1})

    def test_migration_does_not_mutate_defaults(self):
        cfg=m._merge_defaults({});cfg['services']['radarr']['url']='changed'
        self.assertNotEqual(m.DEFAULT_CONFIG['services']['radarr']['url'],'changed')

    def test_legacy_seerr_migration(self):
        cfg=m._merge_defaults({'services':{'jellyseerr':{'api_key':'key','url':'http://old','disabled':False}}})
        self.assertEqual(cfg['services']['seerr']['api_key'],'key')
        self.assertNotIn('jellyseerr',cfg['services'])

    def test_instance_selection_never_guesses(self):
        self.enable('radarr');self.enable('radarr','radarr_4k')
        self.assertIsNone(m.resolve_media_service(self.cfg,'movie'))
        self.assertEqual(m.resolve_media_service(self.cfg,'movie','radarr_4k'),'radarr_4k')
        self.assertIsNone(m.resolve_media_service(self.cfg,'series','radarr_4k'))
        self.assertEqual(len(m.queue_instances(self.cfg)),2)

    def test_service_type_validation(self):
        self.enable('radarr','radarr_4k')['type']='qbit'
        with self.assertRaises(ValueError):m.validate_config(self.cfg)

    def test_duplicate_prowlarr_uses_v1(self):
        svc=self.enable('prowlarr','prowlarr_2')
        with patch.object(m,'http_get',side_effect=[(200,'{}'),(200,'[]')]) as get:
            self.assertEqual(m.check_arr('prowlarr_2',svc)['level'],'ok')
        self.assertTrue(all('/api/v1/' in c.args[0] for c in get.call_args_list))

    def test_add_uses_selected_instance_and_root(self):
        svc=self.enable('radarr','radarr_4k');svc['url']='http://fourk'
        roots=json.dumps([{'path':'/movies'},{'path':'/4k'}]);profiles='[{"id":2,"name":"4k"}]'
        with patch.object(m,'http_get',side_effect=[(200,roots),(200,profiles)]),patch.object(m,'_arr_post',return_value=(201,'{}')) as post:
            result=m.media_add(self.cfg,'movie',{'title':'Film','tmdbId':12},2,'radarr_4k','/4k')
        self.assertTrue(result['ok']);self.assertEqual(post.call_args.args[0],'http://fourk')
        self.assertEqual(post.call_args.args[3]['rootFolderPath'],'/4k')

    def test_books_are_explicitly_search_only(self):
        self.assertFalse(m.media_add(self.cfg,'book',{})['ok'])

    def test_queue_fix_revalidates_identity(self):
        svc=self.enable('radarr')
        with patch.object(m,'http_get',return_value=(200,'{"movieId":99}')),patch.object(m,'_http_request') as mutate:
            result=m.action_queue_fix('radarr',svc,{'queue_id':1,'ids':[1]})
        self.assertFalse(result['ok']);mutate.assert_not_called()

    def test_queue_fix_partial_result(self):
        svc=self.enable('radarr')
        with patch.object(m,'http_get',return_value=(200,'{"movieId":1}')),patch.object(m,'_http_request',side_effect=[(200,''),OSError('search unavailable')]):
            result=m.execute_action(self.cfg,'radarr','queue_fix',{'queue_id':1,'ids':[1]})
        self.assertTrue(result['partial']);self.assertFalse(result['ok'])
        self.assertEqual(m._read_json(m.ACTION_FILE,[])[0]['status'],'partial')

    def test_wrong_service_action_rejected(self):
        self.enable('qbittorrent')
        with patch.object(m,'_http_request') as mutate:
            result=m.execute_action(self.cfg,'qbittorrent','queue_fix',{'queue_id':1})
        self.assertFalse(result['ok']);mutate.assert_not_called()

    def test_blocklist_pagination_and_failure(self):
        with patch.object(m,'http_get',side_effect=[(200,json.dumps({'records':[{'movieId':1}],'totalRecords':201})),(200,json.dumps({'records':[{'movieId':1}],'totalRecords':201}))]):
            self.assertEqual(m._arr_blocklist_counts('http://x','key','movieId',[1]),{1:2})
        with patch.object(m,'http_get',side_effect=OSError()):
            self.assertIsNone(m._arr_blocklist_counts('http://x','key','movieId',[1]))

    def scan(self, counts, result=None):
        self.enable('radarr');self.enable('qbittorrent')
        self.cfg['beta'].update(malware_autoremove=True,malware_extensions=['exe'])
        results={'radarr':{'level':'ok','errors':[]}}
        with patch.object(m,'_qbit_login',return_value=('http://x','cookie')),patch.object(m,'http_get',return_value=(200,'[{"hash":"abc"}]')),patch.object(m,'arr_queue_records',return_value=[{'id':1,'movieId':1,'downloadId':'abc'}]),patch.object(m,'_qbit_scan_files',return_value=['bad.exe']),patch.object(m,'_arr_blocklist_counts',return_value=counts),patch.object(m,'execute_action',return_value=result or {'ok':False,'error':'Removal failed'}) as action:
            m.scan_blocked_files(self.cfg,results)
        return results,action

    def test_failed_auto_remove_not_reported_successful(self):
        result,action=self.scan({})
        self.assertIn('Removal failed',result['radarr']['errors'][0]['message'])
        self.assertEqual(action.call_count,1)

    def test_auto_remove_stops_when_guard_unavailable(self):
        result,action=self.scan(None)
        action.assert_not_called();self.assertIn('cannot verify',result['radarr']['errors'][0]['message'])

    def test_scan_cache_changes_with_extensions(self):
        self.enable('radarr');self.enable('qbittorrent')
        self.cfg['beta'].update(malware_autoremove=False,malware_extensions=['exe'])
        with patch.object(m,'_qbit_login',return_value=('http://x','cookie')),patch.object(m,'http_get',return_value=(200,'[{"hash":"abc"}]')),patch.object(m,'arr_queue_records',return_value=[{'id':1,'movieId':1,'downloadId':'abc'}]),patch.object(m,'_qbit_scan_files',side_effect=[[],['bad.scr']]) as scan:
            m.scan_blocked_files(self.cfg,{'radarr':{'level':'ok','errors':[]}})
            self.cfg['beta']['malware_extensions']=['exe','scr']
            result={'radarr':{'level':'ok','errors':[]}}
            m.scan_blocked_files(self.cfg,result)
        self.assertEqual(scan.call_count,2)
        self.assertIn('bad.scr',result['radarr']['errors'][0]['message'])

    def test_remote_folder_id_selects_private_path(self):
        self.enable('radarr')
        with patch.object(m,'http_get',side_effect=[(200,'[{"id":1,"path":"/first"},{"id":2,"path":"/second"}]'),(200,'[{"id":1}]')]),patch.object(m,'_arr_post',return_value=(201,'{}')) as post:
            self.assertTrue(m.media_add(self.cfg,'movie',{'tmdbId':1},1,'radarr',2)['ok'])
        self.assertEqual(post.call_args.args[3]['rootFolderPath'],'/second')

    def test_stable_update_supersedes_candidate(self):
        self.assertTrue(m._is_newer('v2.0.0','v2.0.0-rc.1'))
        self.assertFalse(m._is_newer('v1.4.1','v2.0.0-rc.1'))

    def test_correlated_removal_keeps_arr_target(self):
        svc=self.enable('radarr','radarr_4k');self.enable('qbittorrent','qbit_2')
        torrent=m.svc_result('qbit_2','error','failed',[dict(m._issue('error','Film','Torrent state: error'),hash='a'*40,state='error')])
        results={'radarr_4k':m.svc_result('radarr_4k','ok','Healthy',[]),'qbit_2':torrent}
        record={'id':1,'movieId':1,'downloadId':'a'*40,'status':'failed','trackedDownloadStatus':'error','title':'Film'}
        with patch.object(m,'http_get',return_value=(200,json.dumps({'records':[record]}))),patch.object(m,'_arr_blocklist_counts',return_value={}):
            m.augment_queue_issues(self.cfg,results)
        actions=results['qbit_2']['errors'][0]['actions']
        self.assertEqual(next(a for a in actions if a['action']=='queue_fix')['service'],'radarr_4k')
        self.assertEqual(next(a for a in actions if a['action']=='qbit_recheck')['service'],'qbit_2')

    def test_multiple_download_clients_and_queue_deduplication(self):
        self.enable('qbittorrent');self.enable('sabnzbd');self.enable('radarr')
        with patch.object(m,'_get_torrents_qbit',return_value={'downloading':[{'id':'abc','name':'Torrent'}],'seeding':[]}),patch.object(m,'sab_data',return_value={'slots':[{'nzo_id':'SAB1','filename':'Usenet','percentage':'50','mb':'100','timeleft':'00:02:00'}]}),patch.object(m,'arr_queue_records',return_value=[{'downloadId':'abc'},{'downloadId':'SAB1'},{'downloadId':'other','title':'Fallback','size':100,'sizeleft':25}]):
            result=m.get_torrents(self.cfg)
        self.assertEqual(len(result['downloading']),3)
        self.assertEqual(result['downloading'][1]['eta'],120)

    def test_multi_server_stats_and_poster_instance(self):
        self.enable('plex','plex_two')['token']='plex-token'
        self.enable('jellyfin')
        with patch.object(m,'_plex_sessions',return_value={'streams':[{'thumb':'/image','mode':'direct'}]}),patch.object(m,'_jellyfin_sessions',return_value={'streams':[]}),patch.object(m,'_plex_library_counts',return_value={'movies':10}),patch.object(m,'_jellyfin_library_counts',return_value={'movies':7}),patch.object(m,'get_torrents',return_value={'ok':True}):
            result=m._compute_stats(self.cfg)
        self.assertEqual(result['movies'],10)
        self.assertEqual(len(result['library_by_server']),2)
        self.assertEqual(result['now_playing']['streams'][0]['instance'],'plex_two')
        with patch.object(m,'get_stats',return_value=result),patch.object(m,'_fetch_bytes',return_value=(b'png','image/png')) as fetch:
            self.assertEqual(m.get_poster(self.cfg,0)[0],b'png')
        self.assertIn('X-Plex-Token=plex-token',fetch.call_args.args[0])

    def test_disabled_actions_and_duplicate_inflight(self):
        svc=self.enable('radarr')
        svc['disabled']=True
        self.assertFalse(m.execute_action(self.cfg,'radarr','test_indexers',{})['ok'])
        svc['disabled']=False
        m._ACTION_RUNNING.add(('radarr','test_indexers','{}'))
        with patch.dict(m.ACTIONS,{'test_indexers':lambda *a:self.fail('must not repeat')}):
            self.assertIn('already running',m.execute_action(self.cfg,'radarr','test_indexers',{})['error'])

    @unittest.skipUnless(os.name == 'posix', 'Unix socket test runs in Linux CI')
    def test_docker_unix_socket_get_only(self):
        import socket
        path=self.file('engine.sock')
        server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        server.bind(path);server.listen(1)
        seen=[]
        def serve():
            conn,_=server.accept()
            with conn:
                seen.append(conn.recv(4096).decode())
                conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n[]')
            server.close()
        thread=threading.Thread(target=serve,daemon=True);thread.start()
        self.assertEqual(m.docker_containers({'url':'unix://'+path}),[])
        thread.join(2)
        self.assertTrue(seen[0].startswith('GET /containers/json?all=1 '))

    def test_observed_health_excludes_unobserved_time(self):
        with patch.object(m.time,'time',return_value=1000):m.record_observations({'a':{'level':'ok'}},30)
        with patch.object(m.time,'time',return_value=1030):m.record_observations({'a':{'level':'error'}},30)
        with patch.object(m.time,'time',return_value=1060):
            m.record_observations({'a':{'level':'error'}},30)
            self.assertEqual(m.uptime_percentages()['a'],50)
        m._OBS_LAST.clear()
        with patch.object(m.time,'time',return_value=5000):
            m.record_observations({'a':{'level':'ok'}},30)
            self.assertEqual(m.uptime_percentages()['a'],50)

    def test_history_retains_boundary_state(self):
        now=time.time();events=[{'service':'a','kind':'down','ts':now-40*86400},{'service':'a','kind':'recover','ts':now}]
        self.assertEqual(len(m._prune_history(events)),2)

    def test_remote_redacts_all_nested_responses(self):
        self.enable('radarr')
        data={'summary':'private-api-key http://media.internal:1234 /mnt/media/movie/file C:\\Media\\test 192.168.2.1',
              'nested':[{'api_key':'private-api-key','url':'http://media.internal','path':'/mnt/media'}]}
        raw=json.dumps(m.public_payload(data,self.cfg))
        for secret in ('private-api-key','media.internal','192.168.2.1','/mnt/media','Media'):
            self.assertNotIn(secret,raw)

    def test_docker_states_and_missing_filter(self):
        svc=self.enable('docker');svc['containers']='good,bad,missing'
        with patch.object(m,'docker_containers',return_value=[{'Names':['/good'],'State':'running','Status':'Up (healthy)'},{'Names':['/bad'],'State':'running','Status':'Up (unhealthy)'},{'Names':['/ignored'],'State':'exited'}]):
            result=m.check_docker('docker',svc)
        self.assertEqual(len(result['errors']),2)

    def test_cleanuparr_health_and_manual_events(self):
        svc=self.enable('cleanuparr')
        with patch.object(m,'http_get',side_effect=[(200,'{"status":"healthy","entries":{}}'),(200,'{"items":[{"id":"1","severity":"Error","message":"Fix import","itemTitle":"Film"}]}')]):
            result=m.check_cleanuparr('cleanuparr',svc)
        self.assertEqual(result['level'],'error');self.assertEqual(result['errors'][0]['message'],'Fix import')

    def test_sab_queue_and_recent_failed_download(self):
        svc=self.enable('sabnzbd')
        with patch.object(m,'sab_data',side_effect=[{'paused':True,'slots':[]},{'slots':[{'status':'Failed','completed':time.time(),'fail_message':'Repair failed','name':'Film'}]}]):
            result=m.check_sabnzbd('sabnzbd',svc)
        self.assertEqual(result['level'],'error');self.assertEqual(len(result['errors']),2)

    def test_poll_checks_concurrently(self):
        self.enable('tunarr');self.enable('tunarr','tunarr_2')
        self.cfg['beta']['remediation']=False
        m.CONFIG.update(self.cfg)
        barrier=threading.Barrier(2)
        def check(name,svc):
            barrier.wait(timeout=2)
            return m.svc_result(name,'ok','Healthy',[])
        with patch.dict(m.CHECKERS,{'tunarr':check}),patch.object(m,'maybe_notify'),patch.object(m,'check_torrent_completions'):
            m.run_poll_once()
        self.assertTrue(all(r['level']=='ok' for r in m.STATE['services'].values()))

    def server(self, public):
        server=socketserver.ThreadingTCPServer(('127.0.0.1',0),m.Handler)
        server.daemon_threads=True;server.is_public=public
        threading.Thread(target=server.serve_forever,daemon=True).start()
        self.addCleanup(server.server_close);self.addCleanup(server.shutdown)
        return 'http://127.0.0.1:'+str(server.server_address[1])

    def request(self,base,path,data=None,headers=None):
        req=urllib.request.Request(base+path,data=json.dumps(data).encode() if data is not None else None,headers={"Content-Type":"application/json", **(headers or {})})
        try:
            with urllib.request.urlopen(req,timeout=5) as r:return r.status,json.loads(r.read())
        except urllib.error.HTTPError as e:return e.code,json.loads(e.read())

    def test_public_routes_and_permissions(self):
        self.enable('radarr');m.CONFIG.update(self.cfg);m.CONFIG['public'].update(enabled=True,token='remote-secret')
        base=self.server(True);token={'X-GT-Token':'remote-secret'}
        self.assertEqual(self.request(base,'/api/status')[0],401)
        self.assertEqual(self.request(base,'/api/config',headers=token)[0],404)
        self.assertEqual(self.request(base,'/api/config',{'config':self.cfg},token)[0],404)
        self.assertEqual(self.request(base,'/api/search',{'term':'film'},token)[0],403)
        self.assertEqual(self.request(base,'/api/action',{},token)[0],403)
        self.assertEqual(self.request(base,'/api/status?t=remote-secret')[0],200)
        code,data=self.request(base,'/api/status',headers=token)
        self.assertEqual(code,200);self.assertNotIn('private-api-key',json.dumps(data));self.assertNotIn('media.internal',json.dumps(data))

    def test_bad_post_and_cross_origin_rejected(self):
        base=self.server(False)
        self.assertEqual(self.request(base,'/api/config',[])[0],400)
        self.assertEqual(self.request(base,'/api/refresh',{}, {'Origin':'https://evil.invalid'})[0],403)

    def test_cross_origin_redirect_rejected(self):
        req=urllib.request.Request('http://service.test/api',headers={'X-Api-Key':'secret'})
        handler=m.SameOriginRedirect()
        with self.assertRaises(urllib.error.HTTPError):
            handler.redirect_request(req,None,302,'Found',{},'http://other.test/api')
        with self.assertRaises(urllib.error.HTTPError):
            handler.redirect_request(req,None,302,'Found',{},'https://service.test/api')
        redirected=handler.redirect_request(req,None,302,'Found',{},'http://service.test/next')
        self.assertEqual(redirected.full_url,'http://service.test/next')

    def test_browser_simple_posts_rejected(self):
        base=self.server(False)
        self.assertEqual(self.request(base,'/api/refresh',{}, {'Content-Type':'text/plain'})[0],415)
        self.assertEqual(self.request(base,'/api/refresh',{}, {'Sec-Fetch-Site':'cross-site'})[0],403)

    def test_poster_rejects_active_content_and_large_files(self):
        for content_type, data in [('image/svg+xml',b'<svg/>'),('text/html',b'<script/>'),('image/png',b'x'*(5*1024*1024+1))]:
            response=unittest.mock.MagicMock()
            response.__enter__.return_value=response
            response.headers={'Content-Type':content_type}
            response.read.return_value=data
            with patch.object(m,'safe_urlopen',return_value=response):
                self.assertEqual(m._fetch_bytes('https://images.test/poster'),(None,None))
        self.assertEqual(m._fetch_bytes('file:///private-file'),(None,None))

    def test_page_security_headers(self):
        base=self.server(False)
        with urllib.request.urlopen(base) as response:
            self.assertEqual(response.headers['X-Frame-Options'],'DENY')
            self.assertEqual(response.headers['Referrer-Policy'],'no-referrer')
            self.assertIn("frame-ancestors 'none'",response.headers['Content-Security-Policy'])

    def test_saved_config_only_updates_memory_after_disk_success(self):
        base=self.server(False)
        changed=copy.deepcopy(self.cfg);changed['theme']='dark'
        with patch.object(m,'save_config',side_effect=OSError()):
            self.assertEqual(self.request(base,'/api/config',{'config':changed})[0],500)
        self.assertEqual(m.CONFIG['theme'],'auto')


if __name__=='__main__':
    unittest.main()
