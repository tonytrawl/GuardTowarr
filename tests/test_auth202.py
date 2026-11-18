"""2.0.2 auth compatibility and diagnostics. All traffic stays on loopback."""
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
from test_monitor import m

class Auth202Tests(unittest.TestCase):
    def setUp(self):
        m._QBIT_SESSIONS.clear()
        self.cookie='QBT_SID_8080';self.login_status=200;self.api_status=200;self.calls=[]
        owner=self
        class API(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_POST(self):self.respond()
            def do_GET(self):self.respond()
            def respond(self):
                self.rfile.read(int(self.headers.get('Content-Length',0)))
                owner.calls.append((self.command,self.path,dict(self.headers)))
                login=self.path.endswith('/auth/login')
                jelly=self.path.startswith('/jellyfin/')
                status=owner.login_status if login else owner.api_status
                if jelly and self.headers.get('Authorization')!=m.jellyfin_headers('fixture-key')['Authorization']:status=401
                if not jelly and not login and self.headers.get('Authorization')!='Bearer fixture-key':
                    if owner.cookie and self.headers.get('Cookie')!=owner.cookie+'=fixture-session':status=403
                self.send_response(status)
                if login and owner.cookie:
                    self.send_header('Set-Cookie','unrelated=not-forwarded; Path=/')
                    self.send_header('Set-Cookie',owner.cookie+'=fixture-session; HttpOnly; SameSite=Strict; Path=/')
                self.end_headers()
                if status>=400:body='fixture-key fixture-session private-server.invalid /private/path HTTP error body'
                elif login:body='' if owner.login_status==204 else 'Ok.'
                elif self.path.endswith('/Items/Counts'):body='{"MovieCount":12,"EpisodeCount":34}'
                elif self.path.endswith('/System/Info'):body='{"Version":"fixture"}'
                elif self.path.endswith('/Sessions'):body='[{"NowPlayingItem":{"Name":"Demo","Type":"Movie"},"UserName":"fixture"}]'
                else:body='[]'
                self.wfile.write(body.encode())
        self.server=ThreadingHTTPServer(('127.0.0.1',0),API)
        threading.Thread(target=self.server.serve_forever,daemon=True).start()
        self.addCleanup(self.server.server_close);self.addCleanup(self.server.shutdown)
        self.base='http://127.0.0.1:'+str(self.server.server_port)
        self.svc={'url':self.base+'/qbit','username':'fixture-user','password':'fixture-password','type':'qbit'}
    def test_legacy_and_port_cookie_reads_actions_and_reuse(self):
        for cookie in ['SID','QBT_SID_8080','QBT_SID_9000']:
            with self.subTest(cookie=cookie):
                m._QBIT_SESSIONS.clear();self.calls.clear();self.cookie=cookie
                self.assertEqual(m._qbit_request(self.svc,'torrents/info')[0],200)
                self.assertEqual(m._qbit_request(self.svc,'torrents/files?hash='+'a'*40)[0],200)
                self.assertTrue(m._qbit_torrent_op(self.svc,'recheck',['a'*40])['ok'])
                self.assertEqual(sum(path.endswith('/auth/login') for _,path,_ in self.calls),1)
                for _,_,headers in self.calls[1:]:self.assertEqual(headers['Cookie'],cookie+'=fixture-session')
    def test_auth_bypass_without_cookie(self):
        self.cookie='';self.assertEqual(m._qbit_request(self.svc,'torrents/info')[0],200)
    def test_login_403_diagnostic_is_safe(self):
        self.login_status=403
        with self.assertRaises(m.QbitRequestError) as err:m._qbit_request(self.svc,'torrents/info')
        self.assertIn('POST /api/v2/auth/login: HTTP 403',str(err.exception));self.assertIn('auth=username/password',str(err.exception))
        self.assertNotIn('fixture-password',str(err.exception));self.assertNotIn('private-server',str(err.exception))
    def test_api_key_failure_endpoint_and_no_fallback(self):
        self.svc['api_key']='fixture-key';self.api_status=403
        with self.assertRaises(m.QbitRequestError) as err:m._qbit_request(self.svc,'torrents/files?hash=private-hash')
        message=str(err.exception)
        self.assertIn('GET /api/v2/torrents/files: HTTP 403',message);self.assertIn('auth=API-key',message)
        for secret in ['fixture-key','private-hash','fixture-session','private-server']:self.assertNotIn(secret,message)
        self.assertEqual(len(self.calls),1)
    def test_non_auth_http_failure(self):
        self.svc['api_key']='fixture-key';self.api_status=404
        with self.assertRaisesRegex(m.QbitRequestError,'HTTP 404'):m._qbit_request(self.svc,'torrents/info')
    def test_transport_exception_text_not_exposed(self):
        for svc in [self.svc,{**self.svc,'api_key':'fixture-key'}]:
            with patch.object(m,'safe_urlopen',side_effect=m.urllib.error.URLError('fixture-password private-server.invalid')):
                with self.assertRaises(m.QbitRequestError) as err:m._qbit_request(svc,'torrents/info')
                self.assertIn('connection/TLS failure',str(err.exception));self.assertNotIn('private-server',str(err.exception))
    def test_jellyfin_all_three_calls_use_standard_auth(self):
        svc={'url':self.base+'/jellyfin','api_key':'fixture-key'}
        self.assertEqual(m.check_jellyfin('jellyfin',svc)['level'],'ok')
        self.assertIsNotNone(m._jellyfin_sessions(svc))
        self.assertEqual(m._jellyfin_library_counts(svc),{'movies':12,'episodes':34})
        self.assertEqual(len(self.calls),3)
        for _,path,headers in self.calls:
            self.assertIn('MediaBrowser Client="GuardTowarr"',headers['Authorization']);self.assertNotIn('X-Emby-Token',headers)
            self.assertNotIn('fixture-key',path)
    def test_jellyfin_401_is_auth_not_unreachable(self):
        self.api_status=401
        result=m.check_jellyfin('jellyfin',{'url':self.base+'/jellyfin','api_key':'fixture-key'})
        self.assertIn('HTTP 401',result['summary']);self.assertNotIn('Unreachable',result['summary'])
        self.assertNotIn('fixture-key',json.dumps(result))
    def test_jellyfin_header_quotes_and_controls(self):
        header=m.jellyfin_headers('a"b\\c')['Authorization']
        self.assertIn('Token="a\\"b\\\\c"',header)
        with self.assertRaises(ValueError):m.jellyfin_headers('bad\r\nInjected: true')

    def test_malformed_http_and_cookie_errors_do_not_expose_server_text(self):
        for api_key in ['', 'fixture-key']:
            for error in [m.http.client.BadStatusLine('fixture-sensitive-response'),m.CookieError('fixture-sensitive-cookie')]:
                svc={**self.svc,'api_key':api_key}
                with patch.object(m,'safe_urlopen',side_effect=error):
                    result=m.check_qbit('qbittorrent',svc)
                self.assertEqual(result['level'],'error')
                self.assertNotIn('fixture-sensitive',json.dumps(result))
                self.assertIn('connection/TLS failure',result['summary'])
    def test_new_auth_headers_cannot_cross_origin_or_downgrade(self):
        for headers in [m.jellyfin_headers('fixture-key'),{'Cookie':'QBT_SID_8080=fixture-session'},{'Authorization':'Bearer fixture-key'}]:
            req=m.urllib.request.Request('https://service.example/api',headers=headers)
            for target in ['https://other.example/api','https://service.example:8443/api','http://service.example/api']:
                with self.assertRaises(m.urllib.error.HTTPError):
                    m.SameOriginRedirect().redirect_request(req,None,302,'Found',{},target)
            redirected=m.SameOriginRedirect().redirect_request(req,None,302,'Found',{},'https://service.example/next')
            self.assertEqual(dict(redirected.header_items()),dict(req.header_items()))

    def test_api_key_matches_qbittorrent_530_bearer_auth(self):
        svc={**self.svc,'api_key':'fixture-key'}
        self.assertEqual(m._qbit_request(svc,'torrents/info')[0],200)
        self.assertEqual(len(self.calls),1)
        self.assertEqual(self.calls[0][2]['Authorization'],'Bearer fixture-key')
        self.assertNotIn('X-Api-Key',self.calls[0][2])
        self.assertNotIn('Cookie',self.calls[0][2])

    def test_modern_204_login_with_cookie(self):
        self.login_status=204
        self.assertEqual(m._qbit_request(self.svc,'torrents/info')[0],200)
        self.assertEqual(self.calls[-1][2]['Cookie'],'QBT_SID_8080=fixture-session')
    def test_empty_204_without_session_cookie_is_not_assumed_authenticated(self):
        self.login_status=204;self.cookie=''
        with self.assertRaisesRegex(m.QbitRequestError,'HTTP 204'):m._qbit_request(self.svc,'torrents/info')
        self.assertEqual(len(self.calls),1)
