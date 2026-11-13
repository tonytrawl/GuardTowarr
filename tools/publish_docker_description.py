"""Sync the public Docker Hub description during the release workflow."""
import json
import os
from pathlib import Path
import urllib.request

base = 'https://hub.docker.com/v2'
body = json.dumps({'username': os.environ['DOCKERHUB_USERNAME'], 'password': os.environ['DOCKERHUB_TOKEN']}).encode()
request = urllib.request.Request(base + '/users/login/', data=body, headers={'Content-Type':'application/json'})
with urllib.request.urlopen(request, timeout=30) as response:
    token = json.load(response)['token']
readme = (Path(__file__).resolve().parents[1] / 'README.md').read_text(encoding='utf-8')
for target in ('LICENSE', 'RELEASE_NOTES_v2.0.0.md', 'docs/2.0.md'):
    readme = readme.replace('](' + target + ')', '](https://github.com/tonytrawl/GuardTowarr/blob/main/' + target + ')')
readme = readme.replace('](../../releases/latest)', '](https://github.com/tonytrawl/GuardTowarr/releases/latest)')
body = json.dumps({'description':"The watchtower for your media stack. It doesn't just tell you what broke, it helps you fix it.", 'full_description':readme}).encode()
request = urllib.request.Request(base + '/repositories/tonytrawl/guardtowarr/', data=body, method='PATCH', headers={'Content-Type':'application/json','Authorization':'JWT ' + token})
with urllib.request.urlopen(request, timeout=30) as response:
    if response.status != 200:
        raise RuntimeError('Docker Hub description update failed')
print('Docker Hub description updated.')
