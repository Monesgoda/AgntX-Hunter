#!/usr/bin/env python3
"""Portable, preservation-first installer. Plan by default; explicit --apply writes.

No provider calls, scans, package-manager installs, or process termination.
The caller selects an unambiguous target. Existing workers block upgrades.
"""
from __future__ import annotations
import argparse
import csv
from contextlib import contextmanager
import hashlib
import json
import os
import re
from pathlib import Path, PurePosixPath
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import zipfile

MAX_ARCHIVE_BYTES = 150_000_000
MUTABLE_EXACT = {'opencode.jsonc', 'opencode.json', 'AGENTS.md', 'pentest/scope.json',
                 'pentest/intelligence_source/playbook_index.json', 'token-saver.json'}
SEED_PREFIXES = ('pentest/knowledge/', 'pentest/intelligence_source/playbooks/',
                 'pentest/references/', 'legacy/skills-original/')

def sha(data):
    return hashlib.sha256(data).hexdigest()

def checked_name(name):
    if not isinstance(name, str) or not name or '\\' in name or '\x00' in name:
        raise ValueError('invalid archive path')
    p = PurePosixPath(name)
    if p.is_absolute() or any(x in ('', '.', '..') or ':' in x for x in name.rstrip('/').split('/')):
        raise ValueError('unsafe archive path: ' + name)
    # Windows normalization must not turn distinct archive names into one file.
    reserved = {'con', 'prn', 'aux', 'nul'} | {f'{x}{i}' for x in ('com', 'lpt') for i in range(1,10)}
    if any(x.endswith((' ', '.')) or x.split('.')[0].lower() in reserved for x in p.parts):
        raise ValueError('non-portable archive path: ' + name)
    return p.as_posix()

def read_archive(path):
    path = Path(path).resolve()
    files = {}; seen = set(); size = 0
    with zipfile.ZipFile(path) as z:
        for member in z.infolist():
            name = checked_name(member.filename)
            key = name.casefold()
            if key in seen: raise ValueError('case-insensitive duplicate ZIP path: ' + name)
            seen.add(key)
            mode = member.external_attr >> 16
            if stat.S_ISLNK(mode): raise ValueError('ZIP symlink refused: ' + name)
            if member.flag_bits & 1: raise ValueError('encrypted ZIP refused')
            if member.is_dir(): continue
            size += member.file_size
            if size > MAX_ARCHIVE_BYTES or member.file_size > 20_000_000:
                raise ValueError('archive expansion budget exceeded')
            files[name] = z.read(member)  # read() verifies the CRC.
    required = ('RELEASE.json', 'PUBLIC_FILE_SHA256_MANIFEST.json', 'INSTALL.py')
    if not all(x in files for x in required): raise ValueError('not a complete merged release archive')
    manifest = json.loads(files['PUBLIC_FILE_SHA256_MANIFEST.json'])
    expected = manifest.get('files')
    if not isinstance(expected, dict) or set(files) != set(expected) | {'PUBLIC_FILE_SHA256_MANIFEST.json'}:
        raise ValueError('archive manifest inventory mismatch')
    for name, digest in expected.items():
        checked_name(name)
        if sha(files[name]) != digest: raise ValueError('archive manifest hash mismatch: ' + name)
    metadata = json.loads(files['RELEASE.json'])
    if metadata.get('package_id') != 'opencode-offsec-merged': raise ValueError('unexpected package identity')
    return files, metadata, sha(path.read_bytes())

def mapped_path(name, layout):
    return name.removeprefix('.opencode/') if layout == 'global' and name.startswith('.opencode/') else name

def mapped_bytes(name, raw, layout):
    if layout == 'global' and (name.startswith(('.opencode/agents/', '.opencode/skills/'))
                              or name in ('pentest/agents/v4-index.json','FRAMEWORK_RULES.md')):
        return raw.decode('utf8').replace('.opencode/', '').encode('utf8')
    return raw

def safe_destination(root, rel):
    checked_name(rel)
    dest = root / rel
    current = dest
    while current != root:
        if current.is_symlink(): raise ValueError('destination symlink refused: ' + rel)
        current = current.parent
    if not dest.resolve().is_relative_to(root.resolve()): raise ValueError('destination escape')
    return dest

def detect_layout(target):
    from SETUP_V4 import EXPECTED_AGENTS
    native,flat=target/'.opencode/agents',target/'agents'
    a=any((native/(name+'.md')).is_file() for name in EXPECTED_AGENTS)
    b=any((flat/(name+'.md')).is_file() for name in EXPECTED_AGENTS)
    if a and b:raise ValueError('both project and global framework agent layouts exist; select/reconcile the active tree first')
    if a or b:return 'global' if b else 'project'
    # Preserve layout selection for incomplete installs; two user-only trees
    # still provide no unambiguous framework destination.
    if native.is_dir() and flat.is_dir():raise ValueError('both project and global agent layouts exist; select/reconcile the active tree first')
    return 'global' if flat.is_dir() else 'project'

def busy_state(target):
    """Inspect relevant process associations and DB states; never steal a lease."""
    blockers = []
    dbpath = target / 'pentest/framework-v4.db'
    if dbpath.exists():
        db = sqlite3.connect(dbpath.as_uri() + '?mode=ro', uri=True, timeout=5)
        try:
            tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            for table in ('coordinator_runs', 'tasks', 'poc_dispatch_jobs'):
                if table in tables:
                    statuses = "('starting','running')" if table == 'coordinator_runs' else "('running')"
                    count = db.execute(f'SELECT COUNT(*) FROM {table} WHERE status IN {statuses}').fetchone()[0]
                    if count: blockers.append({'kind': 'running_or_stale_rows', 'table': table, 'count': count})
        finally: db.close()
    here = str(target.resolve()).casefold()
    if os.name == 'nt':
        script = '[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new(); Get-CimInstance Win32_Process | Select-Object ProcessId,Name,CommandLine | ConvertTo-Json -Compress'
        try:
            cp = subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-Command', script],
                                capture_output=True, text=True, encoding='utf8', errors='replace', timeout=20, check=True)
            rows = json.loads(cp.stdout or '[]'); rows = rows if isinstance(rows,list) else [rows]
            for row in rows:
                name = str(row.get('Name','')).lower(); command = str(row.get('CommandLine') or '')
                relevant = 'opencode' in name or 'pentest.framework' in command or 'pentest.unified' in command
                if not relevant or row.get('ProcessId') == os.getpid(): continue
                if here in command.casefold(): blockers.append({'kind':'relevant_process','pid':row['ProcessId']})
                elif 'opencode' in name:
                    explicit=re.search(r'--(?:cwd|directory)\s+(?:"([^"]+)"|(\S+))',command)
                    directory=Path(explicit.group(1) or explicit.group(2)) if explicit else None
                    if directory is None or not directory.is_dir() or directory.resolve()==target.resolve():
                        blockers.append({'kind':'unresolved_opencode_process','pid':row['ProcessId']})
        except (OSError, ValueError, subprocess.SubprocessError):
            blockers.append({'kind':'process_inventory_unavailable'})
    elif Path('/proc').is_dir():
        for proc in Path('/proc').iterdir():
            if not proc.name.isdigit() or int(proc.name) == os.getpid(): continue
            try:
                command = (proc/'cmdline').read_bytes().decode(errors='replace').replace('\x00',' ')
                name = (proc/'comm').read_text(encoding='utf8').strip().lower()
                if 'opencode' not in name and 'pentest.framework' not in command and 'pentest.unified' not in command: continue
                cwd = (proc/'cwd').resolve()
                if cwd == target or cwd.is_relative_to(target) or here in command.casefold():
                    blockers.append({'kind':'relevant_process','pid':int(proc.name)})
            except (OSError, ValueError): continue
    else:
        # macOS: lsof reports cwd without requiring a fixed home path.
        try:
            cp = subprocess.run(['lsof','-a','-c','opencode','-d','cwd','-Fn'],capture_output=True,text=True,timeout=15)
            if cp.returncode not in (0,1): raise OSError('cwd inventory failed')
            if any(line.startswith('n') and (line[1:] == str(target) or line[1:].startswith(str(target)+os.sep)) for line in cp.stdout.splitlines()):
                blockers.append({'kind':'relevant_process'})
        except (OSError, subprocess.SubprocessError): blockers.append({'kind':'process_inventory_unavailable'})
    return blockers

def db_snapshot(path):
    """Canonical old-column data, suitable for checking an additive migration."""
    db = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)
    try:
        if db.execute('PRAGMA quick_check').fetchone()[0] != 'ok': raise ValueError('SQLite quick_check failed')
        if db.execute('PRAGMA foreign_key_check').fetchall(): raise ValueError('SQLite foreign_key_check failed')
        result = {}
        for (name,) in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"):
            q = '"'+name.replace('"','""')+'"'
            columns = [r[1] for r in db.execute('PRAGMA table_info('+q+')')]
            rows = list(db.execute('SELECT * FROM '+q))
            # SQL values may contain bytes; repr yields deterministic local evidence.
            result[name] = {'columns':columns,'rows':sorted(repr(tuple(r)) for r in rows)}
        return result
    finally: db.close()

def require_preserved(old, path):
    db = sqlite3.connect(path)
    try:
        for table, item in old.items():
            if table == 'meta': continue  # schema metadata is expected to change.
            q = lambda x: '"'+x.replace('"','""')+'"'
            current = collections_counter(repr(tuple(r)) for r in db.execute('SELECT '+','.join(map(q,item['columns']))+' FROM '+q(table)))
            previous = collections_counter(item['rows'])
            if previous - current: raise ValueError('migration changed existing rows: '+table)
    finally: db.close()

def collections_counter(values):
    from collections import Counter
    return Counter(values)

def secure_private(path):
    """Protect backups before secret-bearing files are copied or written."""
    if os.name!='nt':
        path.chmod(0o700 if path.is_dir() else 0o600)
        return
    identity=subprocess.run(['whoami','/user','/fo','csv','/nh'],capture_output=True,
                            text=True,encoding='utf8',errors='replace',check=True,timeout=15)
    rows=list(csv.reader(identity.stdout.strip().splitlines()))
    sid=rows[-1][-1].strip() if rows else ''
    if not re.fullmatch(r'S-1-[0-9-]+',sid):raise ValueError('cannot resolve the current Windows security identity')
    grant='*'+sid+(':(OI)(CI)F' if path.is_dir() else ':F')
    subprocess.run(['icacls',str(path),'/inheritance:r','/grant:r',grant],
                   capture_output=True,text=True,encoding='utf8',errors='replace',check=True,timeout=20)

def copy_backup(target, destination):
    destination.mkdir(mode=0o700)
    secure_private(destination)
    # Do not copy the source root's broad permissions over the private backup.
    for child in target.iterdir():
        dest=destination/child.name
        if child.is_symlink():dest.symlink_to(os.readlink(child),target_is_directory=child.is_dir())
        elif child.is_dir():shutil.copytree(child,dest,symlinks=True)
        else:shutil.copy2(child,dest)
    # Replace raw SQLite copies with coherent online snapshots; WAL/SHM are not backups.
    for p in target.rglob('*'):
        if not p.is_file() or p.is_symlink() or p.suffix.lower() not in ('.db','.sqlite','.sqlite3'): continue
        with p.open('rb') as stream:
            if stream.read(16) != b'SQLite format 3\x00': continue
        out = destination / p.relative_to(target)
        out.unlink()
        Path(str(out)+'-wal').unlink(missing_ok=True); Path(str(out)+'-shm').unlink(missing_ok=True)
        source = sqlite3.connect(p.as_uri()+'?mode=ro',uri=True,timeout=10)
        dest = sqlite3.connect(out)
        try: source.backup(dest)
        finally: dest.close(); source.close()
        Path(str(out)+'-wal').unlink(missing_ok=True); Path(str(out)+'-shm').unlink(missing_ok=True)
        db_snapshot(out)
    return {p.relative_to(destination).as_posix(): sha(p.read_bytes())
            for p in destination.rglob('*') if p.is_file() and not p.is_symlink()}

def overlay(files, root, layout, preserve=True):
    changed=[]; kept=[]
    for name, raw in files.items():
        raw = mapped_bytes(name,raw,layout)
        rel = mapped_path(name, layout); dest = safe_destination(root, rel)
        seeded = name in MUTABLE_EXACT or name.startswith(SEED_PREFIXES)
        if preserve and dest.exists() and seeded:
            kept.append(rel); continue
        if dest.exists() and dest.read_bytes() == raw:
            if os.name!='nt' and name.endswith('.sh'):dest.chmod(0o755)
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        temp = dest.with_name(dest.name+'.install-tmp')
        with temp.open('xb') as stream: stream.write(raw)
        os.replace(temp, dest)
        if os.name!='nt' and name.endswith('.sh'):dest.chmod(0o755)
        changed.append(rel)
    # Only merge the framework instruction pointer. Provider/model/MCP settings survive.
    config_path = next((root/n for n in ('opencode.json','opencode.jsonc') if (root/n).is_file()), root/'opencode.jsonc')
    # Use the staged parser to support comments and trailing commas; no provider operations.
    import importlib.util
    spec=importlib.util.spec_from_file_location('_merged_jsonc',root/'SETUP_V4.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    config=module.jsonc_load(config_path)
    # Probe the executable selected by START/setup. A quoted OPENCODE_BIN is
    # one path; an invalid explicit override must not select another binary.
    # V2 supports existing V1 permission blocks too. Preserve those and native
    # rule order; injecting native defaults could override user restrictions.
    msg=module.ensure_permissions(config,module.opencode_major())
    print(msg)
    instructions=config.get('instructions',[])
    if not isinstance(instructions,list): raise ValueError('custom instructions must be a list')
    if 'FRAMEWORK_RULES.md' not in instructions: instructions.append('FRAMEWORK_RULES.md')
    config['instructions']=instructions
    if config.get('default_agent') in (None,'pentest-operator','offsec-v4-operator'):
        config['default_agent']=json.loads(files['RELEASE.json'])['main_agent']
    new=(json.dumps(config,ensure_ascii=False,indent=2)+'\n').encode()
    if config_path.read_bytes()!=new:
        config_path.write_bytes(new);changed.append(config_path.relative_to(root).as_posix())
    return sorted(set(changed)), sorted(set(kept))

def run_local(root, *args):
    env=dict(os.environ);env['PYTHONDONTWRITEBYTECODE']='1';env['PYTHONUTF8']='1';env['PYTHONIOENCODING']='utf-8'
    result=subprocess.run([sys.executable,'-B',*args],cwd=root,env=env,capture_output=True,text=True,encoding='utf8',errors='replace',timeout=120)
    if result.returncode: raise ValueError('local check failed: '+' '.join(args)+'\n'+result.stdout[-2000:]+result.stderr[-2000:])
    return result.stdout

@contextmanager
def installation_lock(target):
    target.parent.mkdir(parents=True,exist_ok=True)
    lock=target.parent/('.framework-install-lock-'+sha(os.path.normcase(str(target.resolve())).encode())[:16])
    try:
        fd=os.open(lock,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    except FileExistsError as error:
        raise ValueError('installation lock exists; reconcile its owner before continuing: '+str(lock)) from error
    try:
        with os.fdopen(fd,'w') as stream:stream.write(json.dumps({'pid':os.getpid(),'target':str(target)}))
        yield
    finally:lock.unlink(missing_ok=True)

def install(archive, target, *, apply=False, layout='auto', migrate=False):
    files, metadata, archive_sha=read_archive(archive)
    target=Path(target).expanduser().absolute()
    if target.is_symlink(): raise ValueError('installation root must not be a symlink')
    target=target.resolve()
    if (target/'pentest/framework-v4.db').is_symlink():
        raise ValueError('framework database symlink requires a separately reviewed migration')
    exists=target.exists() and any(target.iterdir())
    if exists and not ((target/'pentest/framework/store.py').is_file() and (target/'pentest/agents/v4-index.json').is_file()):
        raise ValueError('nonempty target is not a confirmed V4 framework; select a fresh folder or migrate the older system manually')
    if layout=='auto': layout=detect_layout(target)
    if exists and layout!=detect_layout(target): raise ValueError('cannot change an existing active layout during upgrade')
    blockers=busy_state(target) if exists else []
    changes=[];preserved=[]
    for name,raw in files.items():
        raw=mapped_bytes(name,raw,layout)
        rel=mapped_path(name,layout);p=safe_destination(target,rel)
        if p.exists() and (name in MUTABLE_EXACT or name.startswith(SEED_PREFIXES)): preserved.append(rel)
        elif not p.exists() or p.read_bytes()!=raw:changes.append(rel)
    result={'status':'BLOCKED' if blockers else 'PLANNED','release':metadata['release'],
            'target':str(target),'layout':layout,'archive_sha256':archive_sha,
            'publisher_authenticity':'not independently verified','blockers':blockers,
            'changed_files':changes,'preserved_files':preserved,'database_migration':bool(migrate)}
    if not apply or blockers:return result
    if exists and Path(__file__).resolve().is_relative_to(target.resolve()):
        raise ValueError('run this installer from staging outside the existing target')
    with installation_lock(target):
        try:return _apply_install(files,metadata,target,layout,migrate,result,exists)
        except (OSError,ValueError,sqlite3.Error,subprocess.SubprocessError) as error:
            return dict(result,status='BLOCKED',error=str(error),blockers=[{'kind':'rehearsal_or_apply_failed'}])


def _apply_install(files,metadata,target,layout,migrate,result,exists):
    # The receipt is installer-owned too; never follow a pre-existing link.
    receipt_path=safe_destination(target,'INSTALL_RECEIPT.json')
    target.parent.mkdir(parents=True,exist_ok=True)
    stamp=time.strftime('%Y%m%dT%H%M%SZ',time.gmtime())+'-'+os.urandom(4).hex()
    backup=target.parent/('.framework-backups-'+stamp)
    result['backup']=str(backup) if exists else None
    old_data=target/'pentest/framework-v4.db'
    old_snapshot=db_snapshot(old_data) if old_data.is_file() else None
    with tempfile.TemporaryDirectory(prefix='framework-rehearsal-',dir=target.parent) as temp:
        mirror=Path(temp)/'mirror'
        if exists:
            hashes=copy_backup(target,backup)
            inventory=backup.parent/(backup.name+'-inventory.json')
            fd=os.open(inventory,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
            try:
                secure_private(inventory)
                with os.fdopen(fd,'w',encoding='utf8') as stream:
                    fd=None;stream.write(json.dumps(hashes,indent=2)+'\n')
            finally:
                if fd is not None:os.close(fd)
            # Verify all backup bytes before touching the target.
            for rel,digest in hashes.items():
                if sha((backup/rel).read_bytes())!=digest:raise ValueError('backup verification failed')
            shutil.copytree(backup,mirror,symlinks=True)
        else:mirror.mkdir()
        overlay(files,mirror,layout)
        run_local(mirror,'VERIFY_PUBLIC_RELEASE.py','--mode','installed')
        if migrate:
            run_local(mirror,'-m','pentest.framework.cli','init-db')
            if old_snapshot:require_preserved(old_snapshot,mirror/'pentest/framework-v4.db')
            db_snapshot(mirror/'pentest/framework-v4.db')
        # Check workers again immediately before the real overlay.
        if exists:
            blockers=busy_state(target)
            if blockers:return dict(result,status='BLOCKED',blockers=blockers,backup=str(backup))
        target.mkdir(parents=True,exist_ok=True)
        before={p.relative_to(target).as_posix() for p in target.rglob('*') if p.is_file()}
        before_dirs={p.relative_to(target).as_posix() for p in target.rglob('*') if p.is_dir()}
        try:
            changed,kept=overlay(files,target,layout)
            if migrate:
                run_local(target,'-m','pentest.framework.cli','init-db')
                if old_snapshot:require_preserved(old_snapshot,target/'pentest/framework-v4.db')
            run_local(target,'VERIFY_PUBLIC_RELEASE.py','--mode','installed')
            receipt=dict(result,status='LIVE UPGRADED' if exists else 'FRESH INSTALLED',
                         changed_files=changed,preserved_files=kept,backup=str(backup) if exists else None,
                         local_integrity='PASS',provider_e2e='NOT TESTED',native_discovery='NOT TESTED')
            temporary=receipt_path.with_name(receipt_path.name+'.install-tmp')
            with temporary.open('xb') as stream:
                stream.write((json.dumps(receipt,ensure_ascii=False,indent=2)+'\n').encode('utf8'))
            os.replace(temporary,receipt_path)
        except Exception:
            # No workers were started by this installer. Restore the complete idle snapshot.
            for p in sorted(target.rglob('*'),reverse=True):
                if p.is_file() and p.relative_to(target).as_posix() not in before:p.unlink()
                elif p.is_dir() and not p.is_symlink() and p.relative_to(target).as_posix() not in before_dirs:p.rmdir()
            if exists:
                for database in backup.rglob('*'):
                    if database.is_file() and database.suffix.lower() in ('.db','.sqlite','.sqlite3'):
                        dest=target/database.relative_to(backup)
                        Path(str(dest)+'-wal').unlink(missing_ok=True)
                        Path(str(dest)+'-shm').unlink(missing_ok=True)
                for p in backup.rglob('*'):
                    rel=p.relative_to(backup);dest=target/rel
                    if p.is_symlink():continue
                    if p.is_file():dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,dest)
            raise
    return receipt

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive',type=Path,required=True)
    parser.add_argument('--target',type=Path,required=True)
    parser.add_argument('--layout',choices=('auto','project','global'),default='auto')
    parser.add_argument('--apply',action='store_true')
    parser.add_argument('--migrate',action='store_true',help='rehearse and apply additive framework DB initialization')
    parser.add_argument('--wait-for-idle',type=int,default=0,help='bounded wait in seconds; never terminates a process or edits a lease')
    args=parser.parse_args(argv)
    try:
        if not 0<=args.wait_for_idle<=86400:raise ValueError('wait budget must be 0..86400 seconds')
        deadline=time.monotonic()+args.wait_for_idle
        while True:
            result=install(args.archive,args.target,apply=args.apply,layout=args.layout,migrate=args.migrate)
            if result['status']!='BLOCKED' or not args.wait_for_idle or time.monotonic()>=deadline:break
            if any(x['kind'] not in ('relevant_process','unresolved_opencode_process') for x in result['blockers']):break
            time.sleep(min(10,max(0,deadline-time.monotonic())))
        print(json.dumps(result,ensure_ascii=True,indent=2))
        return 3 if result['status']=='BLOCKED' else 0
    except (OSError, ValueError, sqlite3.Error, zipfile.BadZipFile, subprocess.SubprocessError) as error:
        print(json.dumps({'status':'BLOCKED','error':str(error)},ensure_ascii=True),file=sys.stderr)
        return 2

if __name__=='__main__':raise SystemExit(main())
