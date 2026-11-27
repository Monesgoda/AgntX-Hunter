#!/usr/bin/env python3
"""Verify exact release bytes, or release-owned installed runtime with preserved user data."""
import argparse
import hashlib
import json
import sys
from pathlib import Path
from INSTALL import MUTABLE_EXACT, SEED_PREFIXES, mapped_path, detect_layout, safe_destination
ROOT=Path(__file__).resolve().parent

def verify(root=ROOT,mode='strict'):
    root=Path(root).resolve()
    if mode not in ('strict','installed'):raise ValueError('unknown mode')
    manifest=json.loads((root/'PUBLIC_FILE_SHA256_MANIFEST.json').read_text(encoding='utf8'))
    files=manifest['files'];layout=detect_layout(root) if mode=='installed' else 'project'
    expected_hashes=manifest.get('global_files',files) if mode=='installed' and layout=='global' else files
    missing=[];changed=[];customized=[];invalid=[];unexpected=[];user_extras=[]
    expected=set()
    for name,digest in files.items():
        rel=mapped_path(name,layout) if mode=='installed' else name
        expected.add(rel)
        try:p=safe_destination(root,rel)
        except ValueError:invalid.append(rel+': unsafe destination');continue
        if p.is_symlink() or not p.is_file():missing.append(rel);continue
        value=hashlib.sha256(p.read_bytes()).hexdigest()
        mutable=mode=='installed' and (name in MUTABLE_EXACT or name.startswith(SEED_PREFIXES))
        # In the global-flat layout the manifest is keyed by the mapped
        # installed path (e.g. agents/foo.md), not the project source path
        # (.opencode/agents/foo.md). Use the destination key after mapping.
        expected_digest=expected_hashes.get(rel,expected_hashes.get(name,digest))
        if value!=expected_digest:
            (customized if mutable else changed).append(rel)
    for config_name in ('opencode.json','opencode.jsonc') if mode=='installed' else ():
        if not (root/config_name).is_file():continue
        try:
            from SETUP_V4 import jsonc_load
            obj=jsonc_load(safe_destination(root,config_name))
            if not isinstance(obj,dict):invalid.append(config_name+': object required')
        except (ValueError,OSError,TypeError):invalid.append(config_name+': invalid JSONC or unsafe destination')
    if mode=='installed' and (root/'pentest/scope.json').is_file():
        try:
            obj=json.loads((root/'pentest/scope.json').read_text(encoding='utf8'))
            if not isinstance(obj,dict) or not isinstance(obj.get('engagements'),(dict,list)):invalid.append('invalid scope structure')
        except (ValueError,OSError):invalid.append('invalid scope JSON')
    expected.add('PUBLIC_FILE_SHA256_MANIFEST.json')
    for p in root.rglob('*'):
        if not p.is_file() and not p.is_symlink():continue
        rel=p.relative_to(root).as_posix()
        if rel in expected:continue
        if rel.startswith('tests/') or '/__pycache__/' in '/'+rel:continue  # contributor test suite is not release content
        if mode=='installed' and p.suffix=='.pyc' and p.parent.name=='__pycache__':
            base=p.name.split('.cpython-')[0].split('.pypy-')[0]+'.py'
            source=(p.parent.parent/base).relative_to(root).as_posix()
            if source in expected:continue
        protected=rel.startswith(('pentest/framework/','framework/'))
        if protected or mode=='strict':unexpected.append(rel)
        else:user_extras.append(rel)
    return {'release':manifest['release'],'mode':mode,'layout':layout,'checked':len(files),'missing':missing,'changed':changed,
            'customized':customized,'invalid':invalid,'unexpected':unexpected,'user_extras':user_extras,
            'status':'FAIL' if missing or changed or invalid or unexpected else 'PASS'}

def main(argv=None):
    p=argparse.ArgumentParser();p.add_argument('--mode',choices=('strict','installed'),default='strict');a=p.parse_args(argv)
    try:result=verify(ROOT,a.mode)
    except (OSError,ValueError,KeyError,TypeError) as e:result={'status':'FAIL','error':str(e)}
    print(json.dumps(result,ensure_ascii=False,indent=2));return int(result['status']!='PASS')
if __name__=='__main__':sys.exit(main())
