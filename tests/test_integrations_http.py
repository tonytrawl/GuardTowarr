"""HTTP integration simulations for optional services, with no external requests.

Run: python -B -m unittest discover -s tests -p test_integrations_http.py -v
"""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import time
import unittest
from urllib.parse import parse_qs, urlsplit
from test_monitor import m


class IntegrationHTTPTests(unittest.TestCase):
    def setUp(self):
        self.scenario = 'healthy'
        self.requests = []
        owner = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_GET(self):
                parsed = urlsplit(self.path)
                query = parse_qs(parsed.query)
                owner.requests.append(('GET', parsed.path))
                code, body = owner.response(parsed.path, query, self.headers)
                raw = body.encode() if isinstance(body, str) else json.dumps(body).encode()
                self.send_response(code)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers(); self.wfile.write(raw)
            def do_POST(self):
                owner.requests.append(('POST', self.path))
                self.send_error(405)
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = 'http://127.0.0.1:' + str(self.server.server_port)
        self.addCleanup(self.cleanup)

    def cleanup(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join()
        self.assertTrue(all(method == 'GET' for method, _ in self.requests))

    def response(self, path, query, headers):
        scenario = self.scenario
        if scenario == 'malformed': return 200, '{invalid'
        if scenario == 'unavailable': return 503, {'error': 'Service unavailable'}
        if path == '/api':
            if query.get('apikey') != ['simulation-key']: return 200, {'error': 'API Key Incorrect'}
            mode = query['mode'][0]
            if mode == 'history':
                if scenario == 'history_unavailable': return 403, {}
                slots = []
                if scenario == 'failed':
                    slots = [{'name':'Synthetic failed download','status':'Failed','completed':time.time(),'fail_message':'Repair failed'},
                             {'name':'Old failure','status':'Failed','completed':time.time()-90000}]
                return 200, {'history': {'slots':slots}}
            return 200, {'queue':{'paused': scenario == 'paused', 'noofslots':1, 'slots':[
                {'filename':'Synthetic download','status':'Failed' if scenario == 'queue_error' else 'Downloading',
                 'mb':'100','percentage':'25','kbpersec':'64','timeleft':'0:01:30','nzo_id':'SABnzbd_simulation'}]}}
        if path.startswith('/health') or path.startswith('/api/manualevents'):
            if headers.get('X-Api-Key') != 'simulation-key': return 401, {}
            if path == '/health/detailed':
                status = {'degraded':'Degraded','unhealthy':'Unhealthy'}.get(scenario,'Healthy')
                return (503 if scenario == 'unhealthy' else 200), {'status':status,'entries':{'Downloader':{'status':status,'description':'Synthetic health check'}}}
            if scenario == 'events_unavailable': return 404, {}
            items = []
            if scenario in ('events','overflow'):
                items = [{'id':'simulation-1','severity':'Error','itemTitle':'Synthetic item','message':'Manual action required','isResolved':False},
                         {'id':'simulation-resolved','severity':'Error','message':'Already resolved','isResolved':True}]
            return 200, {'items':items,'totalCount':150 if scenario == 'overflow' else len(items)}
        if path == '/containers/json':
            if scenario == 'denied': return 403, {}
            if scenario == 'missing': return 200, []
            return 200, [{'Id':'synthetic-id','Names':['/simulation'],'State':'exited' if scenario == 'stopped' else 'running',
                          'Status':'Up 1 minute (unhealthy)' if scenario == 'unhealthy' else 'Exited (0)' if scenario == 'stopped' else 'Up 1 minute'}]
        return 404, {}

    def test_sabnzbd_http_scenarios(self):
        svc = {'url':self.url,'api_key':'simulation-key','type':'sabnzbd','app':'sabnzbd','disabled':False}
        for scenario, level, count in [('healthy','ok',0),('paused','warning',1),('failed','error',1),
                ('queue_error','error',1),('history_unavailable','warning',1),('malformed','error',0),('unavailable','error',0)]:
            with self.subTest(scenario=scenario):
                self.scenario=scenario
                result=m.check_sabnzbd('sabnzbd',svc)
                self.assertEqual(result['level'],level)
                self.assertEqual(len(result['errors']),count)
        self.scenario='healthy'
        self.assertEqual(m.check_sabnzbd('sabnzbd',{**svc,'api_key':'invalid'})['level'],'error')
        feed=m.get_torrents({'services':{'sabnzbd':svc}})
        self.assertFalse(feed['errors'])
        row=feed['downloading'][0]
        self.assertEqual((row['progress'],row['size'],row['dlspeed'],row['eta']),(25,104857600,65536,90))
        self.assertEqual(row['protocol'],'usenet')

    def test_cleanuparr_http_scenarios(self):
        svc = {'url':self.url,'api_key':'simulation-key'}
        for scenario, level, count in [('healthy','ok',0),('degraded','warning',1),('unhealthy','error',1),
                ('events','error',1),('overflow','error',2),('events_unavailable','warning',1),('malformed','error',0)]:
            with self.subTest(scenario=scenario):
                self.scenario=scenario
                result=m.check_cleanuparr('cleanuparr',svc)
                self.assertEqual(result['level'],level)
                self.assertEqual(len(result['errors']),count)
        self.scenario='healthy'
        result=m.check_cleanuparr('cleanuparr',{**svc,'api_key':'invalid'})
        self.assertEqual(result['summary'],'API key rejected')

    def test_docker_proxy_http_scenarios(self):
        svc = {'url':self.url,'containers':'simulation'}
        for scenario, level in [('healthy','ok'),('stopped','error'),('unhealthy','error'),('missing','error'),
                                ('denied','error'),('malformed','error'),('unavailable','error')]:
            with self.subTest(scenario=scenario):
                self.scenario=scenario
                self.assertEqual(m.check_docker('docker',svc)['level'],level)
        self.assertTrue(all(path == '/containers/json' for _,path in self.requests))


if __name__ == '__main__': unittest.main()
