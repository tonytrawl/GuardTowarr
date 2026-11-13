"""Isolated UI preview against simulated services. Never reads the real config."""
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
temp=tempfile.TemporaryDirectory(prefix='guardtowarr-preview-')
os.environ['GUARDTOWARR_CONFIG_DIR']=temp.name
import monitor as m

cfg=m._merge_defaults({})
cfg.update(setup_complete=True,port=19595)
cfg['ui']['update_check']=False
cfg['public'].update(enabled=True,port=19596,token='preview-token',allow_requests=True)
for app,label in [('radarr','Movies'),('sonarr','TV'),('sabnzbd','Usenet'),('docker','Containers'),('cleanuparr','Cleanup')]:
    cfg['services'][app].update(disabled=False,label=label,api_key='fixture-key',url='http://fixture.invalid/'+app)
cfg['services']['radarr_4k']={**cfg['services']['radarr'],'label':'Movies 4K','url':'http://fixture.invalid/radarr_4k'}
cfg['beta']['lite_stats']=True
m.CONFIG.update(cfg);m.save_config(cfg)
m.PAGE=(ROOT/'webpage.html').read_text(encoding='utf-8')

def fake_get(url,*args,**kwargs):
    if '/movie/lookup' in url:return 200,json.dumps([{'title':'Example Movie','year':2026,'tmdbId':123,'images':[]}])
    if '/qualityprofile' in url:return 200,'[{"id":1,"name":"HD"},{"id":2,"name":"Ultra HD"}]'
    if '/rootfolder' in url:return 200,'[{"id":1,"path":"/movies"},{"id":2,"path":"/movies-4k"}]'
    if '/system/status' in url:return 200,'{}'
    if '/health' in url:return 200,'[]'
    if '/queue' in url:return 200,'{"records":[],"totalRecords":0}'
    raise ValueError('Preview only: unsupported request')
m.http_get=fake_get
m._arr_post=lambda *args,**kwargs:(201,'{}')
m.get_torrents=lambda cfg:{'ok':True,'source':'combined','downloading':[{'name':'Example download','state':'Downloading','progress':45,'size':5000000000,'dlspeed':5000000,'eta':600,'protocol':'usenet','client':'Usenet'}],'seeding':[],'errors':[]}
m.check_for_update=lambda **kwargs:{'available':False,'current':m.CURRENT_VERSION}
def update():
    while True:
        results={name:m.svc_result(name,'ok','Healthy',[]) for name,_ in m.active_instances(m.get_config())}
        results['docker']=m.svc_result('docker','error','1 container issue',[m._issue('error','test-container','Container exited: Exit 1')])
        results['cleanuparr']=m.svc_result('cleanuparr','warning','Action required',[m._issue('warning','Example import','Manual import requires attention.')])
        with m.STATE_LOCK:m.STATE.update(services=results,last_poll_epoch=time.time(),last_poll=time.strftime('%Y-%m-%d %H:%M:%S'))
        time.sleep(5)
threading.Thread(target=update,daemon=True).start()
threading.Thread(target=m.run_server,args=(19596,True),daemon=True).start()
print('Isolated preview: http://localhost:19595 ; remote port 19596 token preview-token',flush=True)
m.run_server(19595)
