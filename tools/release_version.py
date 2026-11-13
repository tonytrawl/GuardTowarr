"""Validate source/tag agreement; pre-releases never move latest."""
import ast
from pathlib import Path
import re
import sys
tree = ast.parse((Path(__file__).resolve().parents[1] / 'monitor.py').read_text(encoding='utf-8'))
version = next(n.value.value for n in tree.body if isinstance(n, ast.Assign)
               and any(isinstance(t, ast.Name) and t.id == 'CURRENT_VERSION' for t in n.targets))
tag = sys.argv[1]
if not re.fullmatch(r'v\d+\.\d+\.\d+(?:-[a-zA-Z0-9.]+)?', tag) or version != tag:
    sys.exit(f'Release tag {tag!r} does not match CURRENT_VERSION {version!r}.')
print(f'tag={tag}\nversion={tag[1:]}\nstable={str("-" not in tag).lower()}')
