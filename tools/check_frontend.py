"""Parse inline JavaScript using Node; no npm dependencies."""
from pathlib import Path
import re
import subprocess
import sys
page = Path(__file__).resolve().parents[1] / 'webpage.html'
for script in re.findall(r'<script[^>]*>(.*?)</script>', page.read_text(encoding='utf-8'), re.S):
    if script.strip():
        result = subprocess.run(['node', '--check'], input=script.encode('utf-8'))
        if result.returncode:
            sys.exit(result.returncode)
print('Frontend JavaScript syntax passed.')

# Exercise URL validation and card escaping with hostile upstream values.
source = page.read_text(encoding="utf-8")
functions = []
for name in ("safeHttpUrl", "esc", "buildCard"):
    pattern = (r"function " + name + r"\([^\n]*?\)\{.*?\n\}" if name != "esc"
               else r"function esc\([^\n]+")
    match = re.search(pattern, source, re.S if name != "esc" else 0)
    if not match:
        sys.exit("Missing frontend security helper: " + name)
    functions.append(match.group(0))
checks = r"""
const assert=require('node:assert/strict');
const GT_PUBLIC=false, dismissedMap={}, issueActionsMap={};
function lvlClass(l){return l==='error'?'err':l==='warning'?'warn':'ok';}
assert.equal(safeHttpUrl('javascript:alert(1)'), '');
assert.equal(safeHttpUrl('data:text/html,<script>'), '');
assert.equal(safeHttpUrl('https://user:secret@example.com'), '');
assert.equal(safeHttpUrl('https://example.com/docs'), 'https://example.com/docs');
const card=buildCard({name:'radarr',level:'error',summary:'<img onerror=alert(1)>',errors:[
 {id:'123',level:'error" onmouseover="alert(1)',source:'<script>',message:'<img>',fix:'javascript:alert(1)'}]}, {}, false);
assert.ok(!card.inner.includes('href="javascript:'));
assert.ok(!card.inner.includes('class="issue error" onmouseover='));
assert.ok(card.inner.includes('&lt;img'));
assert.equal(buildCard({name:'radarr',level:'error',errors:[]},{},false).dl,'error');
console.log('Frontend security and status checks passed.');
"""
result=subprocess.run(["node"], input=("\n".join(functions)+"\n"+checks).encode("utf-8"))
sys.exit(result.returncode)
