#!/usr/bin/env python3
"""Read-only startup checks followed by native OpenCode launch, from any cwd."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from VERIFY_PUBLIC_RELEASE import verify
from SETUP_V4 import resolve_opencode_bin

ROOT=Path(__file__).resolve().parent

def main(argv=None):
    parser=argparse.ArgumentParser();parser.add_argument('--check',action='store_true')
    args=parser.parse_args(argv)
    checks=verify(ROOT,'installed')
    if checks['status']!='PASS':
        print(json.dumps(checks,indent=2));return 2
    if not (ROOT/'pentest/framework-v4.db').is_file():
        print('Framework DB missing. Complete the installer with --apply --migrate first.',file=sys.stderr);return 2
    program=resolve_opencode_bin()
    if not program:
        print('OpenCode CLI is missing; install/configure it before startup.',file=sys.stderr);return 2
    # Normalize a quoted override once and pass the selected path to native
    # OpenCode and its framework workers without shell parsing or word splitting.
    env=dict(os.environ);env['OPENCODE_BIN']=program
    try:
        cp=subprocess.run([program,'debug','agents'],cwd=ROOT,env=env,capture_output=True,text=True,encoding='utf8',errors='replace',timeout=60)
    except (OSError,subprocess.SubprocessError):
        print(json.dumps({'status':'BLOCKED','detail':'Native agent discovery could not complete.'}));return 2
    metadata=json.loads((ROOT/'RELEASE.json').read_text(encoding='utf8'))
    registry=json.loads((ROOT/metadata['registry']).read_text(encoding='utf8'))
    names={n for group in registry['categories'].values() for n in group['agents']}
    observed=cp.stdout+cp.stderr
    missing=[name for name in names if not re.search(r'(?<![\w-])'+re.escape(name)+r'(?![\w-])',observed)]
    if cp.returncode or missing:
        print(json.dumps({'status':'BLOCKED','native_discovery_exit':cp.returncode,'missing':sorted(missing),'detail':'Native discovery failed; inspect diagnostics locally without sharing credentials.'},ensure_ascii=False,indent=2));return 2
    if args.check:
        print(json.dumps({'status':'PASS','native_agents':len(names),'provider_e2e':'NOT TESTED'},indent=2));return 0
    return subprocess.call([program,'--agent',metadata['main_agent']],cwd=ROOT,env=env)

if __name__=='__main__':raise SystemExit(main())
