#!/usr/bin/env python3
"""Project-local OpenCode V4 activation. Does not write to user/global config.
Creates project config and validates 17 active agent definitions in OpenCode's discovered location.
Never runs any target scan or installs dependencies.
"""
from __future__ import annotations
import argparse, json, os, re, shutil, subprocess, sys
from pathlib import Path

ROOT=Path(__file__).resolve().parent

EXPECTED_AGENTS = frozenset({
    'offsec-v4-operator', 'offsec-v4-recon-agent', 'offsec-v4-poc-agent',
    'offsec-v4-code-auditor', 'offsec-v4-ctf-solver', 'offsec-v4-enterprise',
    'offsec-v4-malware-analyst', 'offsec-v4-reporting-agent',
    *{'offsec-family-'+name for name in (
        'injection','client-side','access-auth','request-forgery','file-path',
        'business-logic','infra','api','llm-security')},
})
REQUIRED_SKILLS = frozenset({
    'poc-creation', 'offsec-v4-main-agent', 'offsec-v4-recon-agent',
    'offsec-v4-code-auditor', 'offsec-v4-ctf-solver', 'offsec-v4-enterprise',
    'offsec-v4-malware-analyst', 'offsec-v4-reporting-agent',
    'offsec-optional-mobile', 'offsec-enterprise-network', 'offsec-enterprise-ad',
    'offsec-enterprise-cloud', 'offsec-enterprise-container', 'offsec-recon-nmap',
    'offsec-shared-exploit-chaining', 'offsec-shared-payload-design',
    *{'offsec-family-'+name for name in (
        'injection','client-side','access-auth','request-forgery','file-path',
        'business-logic','infra','api','llm-security')},
})

# Defaults from the shipped configs. V2 also supports the V1 permission form;
# keep existing blocks intact so its compatibility loader preserves behavior.
V2_PERMISSIONS=[
  { "action": "shell", "resource": "*", "effect": "ask" },
  { "action": "shell", "resource": "python -m pentest.framework.cli *", "effect": "allow" },
  { "action": "shell", "resource": "python3 -m pentest.framework.cli *", "effect": "allow" },
  { "action": "shell", "resource": "python -m pentest.framework.cli", "effect": "allow" },
  { "action": "shell", "resource": "python3 -m pentest.framework.cli", "effect": "allow" },
  { "action": "shell", "resource": "sqlite3 *", "effect": "deny" },
  { "action": "shell", "resource": "curl *", "effect": "deny" },
  { "action": "shell", "resource": "wget *", "effect": "deny" },
  { "action": "shell", "resource": "nc *", "effect": "deny" },
  { "action": "shell", "resource": "ncat *", "effect": "deny" },
  { "action": "shell", "resource": "ssh *", "effect": "deny" },
  { "action": "shell", "resource": "psql *", "effect": "deny" },
  { "action": "shell", "resource": "mysql *", "effect": "deny" }
]
V1_PERMISSION={
  "edit": "deny",
  "webfetch": "deny",
  "bash": {
    "*": "ask",
    "python -m pentest.framework.cli *": "allow",
    "python3 -m pentest.framework.cli *": "allow",
    "sqlite3 *": "deny", "curl *": "deny", "wget *": "deny", "nc *": "deny", "ssh *": "deny"
  }
}

def resolve_opencode_bin():
    """Resolve one executable, never a shell command; an explicit override is authoritative."""
    configured=os.environ.get('OPENCODE_BIN')
    name=(configured or 'opencode').strip()
    if len(name)>=2 and name[0]==name[-1] and name[0] in ('"',"'"):
        name=name[1:-1]
    names=[name] if configured else [name,'opencode2']
    for name in names:
        if not name:continue
        exe=shutil.which(name) or (str(Path(name).resolve()) if Path(name).is_file() else None)
        if exe:return str(Path(exe).absolute())
    return None

def opencode_major():
    """Probe the same executable used by startup; never fall back after a failed probe."""
    exe=resolve_opencode_bin()
    if exe:
        try:
            cp=subprocess.run([exe,'--version'],capture_output=True,text=True,encoding='utf8',errors='replace',timeout=20)
            m=re.search(r'(\d+)\.\d+',cp.stdout) if cp.returncode==0 else None
            if m:return int(m.group(1))
        except (OSError,subprocess.SubprocessError):pass
    return None

def ensure_permissions(config,major):
    """Add the framework's permission rules for the detected OpenCode major. NEVER overwrite user rules."""
    if major is None: return 'opencode not found/undetectable: existing permission settings preserved; defaults NOT added'
    if major>=2:
        # Supported V1 syntax is normalized in memory by V2. Adding native
        # defaults would override legacy restrictions, including edit/webfetch.
        # Leave both forms alone: valid native values take precedence in V2.
        if 'permission' in config or 'permissions' in config:
            return 'existing user permission rules preserved (including supported V1 compatibility)'
        config['permissions']=json.loads(json.dumps(V2_PERMISSIONS))
        return 'permission rules added for OpenCode '+str(major)+'.x'
    key,wrong=('permissions','permission') if major>=2 else ('permission','permissions')
    if wrong in config:
        ours=(wrong=='permissions' and config[wrong]==V2_PERMISSIONS) or (wrong=='permission' and config[wrong]==V1_PERMISSION)
        if not ours:
            raise ValueError(f'config contains "{wrong}" which OpenCode {major}.x rejects; replace it with "{key}" (see opencode.jsonc)')
        del config[wrong]
        config.setdefault(key,json.loads(json.dumps(V2_PERMISSIONS if major>=2 else V1_PERMISSION)))
        return 'converted the framework permission block to the OpenCode '+str(major)+'.x format'
    if key in config: return 'existing user permission rules preserved'
    config[key]=json.loads(json.dumps(V2_PERMISSIONS if major>=2 else V1_PERMISSION))
    return 'permission rules added for OpenCode '+str(major)+'.x'

def active_paths():
    candidates=[(base/'agents',base/'skills') for base in (ROOT/'.opencode',ROOT)
                if any((base/'agents'/(name+'.md')).is_file() for name in EXPECTED_AGENTS)]
    if len(candidates)>1:raise ValueError('Duplicate active framework agents directories detected')
    if not candidates:raise ValueError('No active V4 framework agent definitions found')
    return candidates[0]

def validate_definition(path, *, skill_name=None):
    """Check the shipped definitions' required frontmatter and nonempty prompt offline."""
    def invalid(detail):
        raise ValueError('Invalid V4 definition '+str(path)+': '+detail)
    if path.is_symlink() or not path.is_file():invalid('regular file required')
    lines=path.read_text(encoding='utf-8-sig').splitlines()
    if not lines or lines[0]!='---':invalid('frontmatter required')
    try:end=lines.index('---',1)
    except ValueError:invalid('unclosed frontmatter')
    if not '\n'.join(lines[end+1:]).strip():invalid('empty instructions')
    fields={}
    for line in lines[1:end]:
        if not line.strip() or line.lstrip().startswith('#') or line[0].isspace():continue
        match=re.fullmatch(r'([\w-]+):[ \t]*(.*)',line)
        if not match or match[1] in fields:invalid('malformed or duplicate frontmatter field')
        fields[match[1]]=match[2]
    def scalar(key):
        value=fields.get(key,'').strip()
        if value.startswith('"'):
            try:value=json.loads(value)
            except ValueError:invalid('invalid '+key+' string')
        elif value.startswith("'"):
            if not value.endswith("'") or len(value)<2:invalid('invalid '+key+' string')
            value=value[1:-1].replace("''", "'")
        else:value=value.split(' #',1)[0].strip()
        if not isinstance(value,str) or not value or value.lower() in ('null','true','false') or value[0] in '[{|>':
            invalid('nonempty scalar '+key+' required')
        return value
    scalar('description')
    if skill_name:
        if scalar('name')!=skill_name:invalid('framework skill name does not match its ID')
    else:
        mode=scalar('mode')
        allowed=('primary','all') if path.stem=='offsec-v4-operator' else ('subagent','all')
        if mode not in allowed:invalid('invalid framework agent mode')
        for key in ('disable','disabled'):
            if key in fields and fields[key].split(' #',1)[0].strip()!='false':invalid('agent must be enabled')

def validate_inventory():
    active,public_skills=active_paths()
    actual_agents={f.stem for f in active.glob('*.md') if f.is_file()}
    missing=EXPECTED_AGENTS-actual_agents
    if missing:raise ValueError('V4 agent inventory mismatch in '+str(active)+': missing='+repr(sorted(missing)))
    actual_skills={x.name for x in public_skills.iterdir() if x.is_dir() and (x/'SKILL.md').is_file()} if public_skills.is_dir() else set()
    missing=REQUIRED_SKILLS-actual_skills
    if missing:raise ValueError('V4 skill inventory mismatch in '+str(public_skills)+': missing='+repr(sorted(missing)))
    # V2 discovers the legacy singular/mode directories too. Only framework IDs
    # are reserved; unrelated user agents and skills can coexist in either tree.
    for base in (ROOT/'.opencode',ROOT):
        for directory in ('agent','agents','mode','modes'):
            for name in EXPECTED_AGENTS:
                path=base/directory/(name+'.md')
                if path.is_file() and path!=active/(name+'.md'):
                    raise ValueError('Duplicate active V4 agent definition: '+str(path))
        for directory in ('skill','skills'):
            source=base/directory
            for path in source.glob('*.md'):
                if path.is_file() and path.stem in REQUIRED_SKILLS:raise ValueError('Duplicate active V4 skill definition: '+str(path))
            # Discovery stops inside a skill and skips hidden/node_modules
            # directories. A user's embedded reference is not another skill.
            pending=[(source,0)] if source.is_dir() else []
            definitions=[]
            while pending:
                folder,depth=pending.pop()
                if folder!=source and (folder/'SKILL.md').is_file():
                    definitions.append(folder/'SKILL.md');continue
                if depth>=6:continue
                pending.extend((child,depth+1) for child in folder.iterdir()
                               if child.is_dir() and not child.name.startswith('.') and child.name!='node_modules')
            for path in definitions:
                if path.parent.name in REQUIRED_SKILLS and path!=public_skills/path.parent.name/'SKILL.md':
                    raise ValueError('Duplicate active V4 skill definition: '+str(path))
    for name in sorted(EXPECTED_AGENTS):validate_definition(active/(name+'.md'))
    for name in sorted(REQUIRED_SKILLS):validate_definition(public_skills/name/'SKILL.md',skill_name=name)
    return active,public_skills

def jsonc_load(path):
    # Remove comments without corrupting strings (including URLs). Remove trailing commas.
    src=Path(path).read_text(encoding='utf-8-sig')
    out=[];i=0;quoted=False;esc=False
    while i<len(src):
        c=src[i]
        if quoted:
            out.append(c)
            if esc:esc=False
            elif c=='\\':esc=True
            elif c=='"':quoted=False
            i+=1;continue
        if c=='"':quoted=True;out.append(c);i+=1;continue
        if src.startswith('//',i):
            while i<len(src) and src[i] not in '\r\n':i+=1
            continue
        if src.startswith('/*',i):
            end=src.find('*/',i+2)
            if end==-1:raise ValueError('Unclosed JSONC comment')
            i=end+2;continue
        out.append(c);i+=1
    # Strip trailing commas only OUTSIDE JSON strings. A regex would corrupt
    # otherwise-valid MCP commands or URLs containing literal ",}" or ",]".
    raw=''.join(out)
    stripped=[];quoted=False;esc=False
    for i,c in enumerate(raw):
        if quoted:
            stripped.append(c)
            if esc:esc=False
            elif c=='\\':esc=True
            elif c=='"':quoted=False
            continue
        if c=='"':quoted=True;stripped.append(c);continue
        if c==',':
            j=i+1
            while j<len(raw) and raw[j].isspace():j+=1
            if j<len(raw) and raw[j] in '}]':continue
        stripped.append(c)
    raw=''.join(stripped)
    obj=json.loads(raw)
    if not isinstance(obj,dict):raise ValueError('OpenCode config must be an object')
    return obj

def profile_files(home):
    p=Path(home)/'.config'/'opencode'
    return [p/'opencode.json',p/'opencode.jsonc']

def create(home=None):
    home=Path(home or Path.home())
    # Single authoritative definitions live in OpenCode's discovered directories.
    # No generated mirrors or filesystem copying: fail closed if files are missing.
    expected=EXPECTED_AGENTS
    active,public_skills=validate_inventory()
    required_skills=sorted(REQUIRED_SKILLS)
    global_path=next((str(config) for config in profile_files(home) if config.is_file()),None)
    # Preserve model/providers/plugins in installed user config via OpenCode global precedence.
    # The project-level settings are the primary role and framework instructions.
    project={'$schema':'https://opencode.ai/config.json','default_agent':'offsec-v4-operator',
             'instructions':['AGENTS.md']}
    statuses={}
    path=next((ROOT/name for name in ('opencode.json','opencode.jsonc') if (ROOT/name).is_file()),ROOT/'opencode.jsonc')
    if path.is_file():
        try:
            previous=jsonc_load(path)
            merged=dict(previous)
            existing_mcp=merged.get('mcp',{})
            if not isinstance(existing_mcp,dict):raise ValueError('Existing MCP must be a mapping')
            generated=project.get('mcp',{})
            for name,value in existing_mcp.items():
                if name in generated and generated[name]!=value:
                    statuses[name]='preserved existing project MCP configuration'
            merged_mcp={**generated,**existing_mcp}
            if merged_mcp:merged['mcp']=merged_mcp
            instructions=merged.get('instructions',[])
            if not isinstance(instructions,list):raise ValueError('Instructions must be an array')
            pointer='FRAMEWORK_RULES.md' if (ROOT/'FRAMEWORK_RULES.md').is_file() else 'AGENTS.md'
            if pointer not in instructions:instructions=[*instructions,pointer]
            merged['instructions']=instructions
            merged.setdefault('$schema','https://opencode.ai/config.json')
            merged.setdefault('default_agent','offsec-v4-operator')
            project=merged
            statuses['existing_config']='preserved provider, model, plugins, custom default and MCP settings'
        except json.JSONDecodeError as exc:raise ValueError('Invalid existing project config: '+str(exc))
    statuses['permissions']=ensure_permissions(project,opencode_major())
    if path.is_symlink():raise ValueError('Project config symlink requires a separately reviewed setup')
    tmp=path.with_name(path.name+'.tmp')
    created=False
    try:
        with tmp.open('x',encoding='utf8') as stream:
            created=True
            stream.write(json.dumps(project,indent=2,ensure_ascii=False)+'\n')
        os.replace(tmp,path)
    except Exception:
        # Do not remove an existing user-owned temporary file on failed creation.
        if created:tmp.unlink(missing_ok=True)
        raise
    report={'status':'configured','root':str(ROOT),'agents':sorted(expected),'agent_definition_location':str(active),'published_skill_count':len(required_skills),
            'project_config':str(path),'global_config':global_path,'global_config_preserved':True,
            'configuration':statuses,'open_code_available':bool(resolve_opencode_bin()),
            'notes':['Existing global provider/model configuration is inherited; it is never overwritten.',
                     'MCP status does not prove connectivity. Use opencode mcp list and check connectivity on this computer.',
                     'No external scan or agent execution was started.',
                     'Permissions: '+statuses['permissions']]}
    (ROOT/'V4_SETUP_REPORT.json').write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding='utf8')
    return report

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--home')
    a=parser.parse_args()
    try:
        print(json.dumps(create(a.home),indent=2,ensure_ascii=False))
    except (ValueError,OSError,KeyError) as ex:
        print(json.dumps({'status':'error','error':str(ex)}),file=sys.stderr);sys.exit(2)
