#!/usr/bin/env python3
"""Pull selected code, build in the project checkout, and restart its services."""
import argparse, fcntl, json, os, pathlib, re, shlex, shutil, signal, socket, subprocess, sys, time, urllib.request, zipfile
P = pathlib.Path
BASE = P('/home/gandiv/projects')
PM2 = '/home/gandiv/.nvm/versions/node/v22.17.1/bin/pm2'

def run(args, cwd=None, capture=False):
    if capture:
        return subprocess.check_output(args, cwd=cwd, env=ENV, text=True)
    with LOG.open('ab') as log:
        child = subprocess.Popen(args, cwd=cwd, env=ENV, stdout=log, stderr=log, start_new_session=True)
        try: code = child.wait()
        except BaseException:
            os.killpg(child.pid, signal.SIGTERM)
            try: child.wait(timeout=5)
            except subprocess.TimeoutExpired: os.killpg(child.pid, signal.SIGKILL)
            raise
    if code:
        raise RuntimeError('Command failed; protected server log: ' + str(LOG))

def atomic_link(target, link):
    temp = link.with_name(link.name + '.new')
    if temp.is_symlink(): temp.unlink()
    temp.symlink_to(target)
    temp.replace(link)

def validate(config, source):
    root = P(config['project'])
    if root.resolve() != root or not root.is_relative_to(BASE) or not (root/'.git').exists():
        raise ValueError('Invalid project root')
    if os.environ.get('GITHUB_REPOSITORY') != config['repository']:
        raise ValueError('Repository mismatch')
    branch = os.environ.get('DEPLOY_BRANCH', '')
    subprocess.run(['git', 'check-ref-format', 'refs/heads/'+branch], check=True, stdout=subprocess.DEVNULL)
    sha = subprocess.check_output(['git','rev-parse','HEAD'],cwd=source,text=True).strip()
    if not re.fullmatch('[0-9a-f]{40}', sha): raise ValueError('Invalid commit')
    expected = os.environ.get('DEPLOY_COMMIT')
    if expected and expected != sha: raise ValueError('Source commit differs from the workflow checkout')
    if subprocess.check_output(['git','status','--porcelain','--untracked-files=all'],cwd=source,text=True).strip():
        raise ValueError('Source checkout contains uncommitted changes')
    for runtime in config['runtimes']:
        if runtime['cwd'] != '.' and ('..' in P(runtime['cwd']).parts or P(runtime['cwd']).is_absolute()):
            raise ValueError('Invalid runtime cwd')
    return root, branch, sha

def build(config, release):
    stack = config['stack']
    if stack in ('npm','pnpm'):
        manager=['corepack','pnpm'] if stack=='pnpm' else ['npm']
        run(manager+(['install','--frozen-lockfile'] if stack=='pnpm' else ['ci','--no-audit','--no-fund']),release)
        for check in config.get('checks',[]): run(check,release)
        for command in config['build']: run(command,release)
    else:
        for command in config['build']: run(command,release)
    for required in config['outputs']:
        if not (release/required).exists(): raise RuntimeError('Required build output missing: '+required)

def pm2_config(config, release, existing):
    apps=[]
    for runtime in config['runtimes']:
        name=runtime['name']; old=existing.get(name)
        # Keep runtime env local. Never put the PM2 environment in GitHub output.
        local_env=dict(old.get('env',{}) if old else {})
        for k in ('ACTIONS_RUNTIME_TOKEN','ACTIONS_ID_TOKEN_REQUEST_TOKEN'):
            local_env.pop(k,None)
        local_env['NODE_ENV']='production'
        app={'name':name,'cwd':str(release/runtime['cwd']), 'args':runtime.get('args',[]),
             'interpreter':runtime['interpreter'], 'env':local_env, 'autorestart':True,
             'restart_delay':30000 if name=='enduser-gw' else 3000, 'max_restarts':10}
        for key in ('namespace','exp_backoff_restart_delay','max_restarts','min_uptime','kill_timeout','listen_timeout','max_memory_restart','node_args'):
            if old and old.get(key) is not None: app[key]=old[key]
        if runtime['kind']=='go':
            wrapper=release/'.deploy'/('start-'+name+'.sh')
            envfile=P(config['project'])/'.env'
            if not envfile.is_file(): raise RuntimeError('Required server .env missing')
            wrapper.write_text('#!/usr/bin/env bash\nset -Eeuo pipefail\nset -a\nsource '+shlex.quote(str(envfile))+'\nset +a\nexec '+shlex.quote(str(release/runtime['script']))+'\n')
            wrapper.chmod(0o700); app['script']=str(wrapper); app['interpreter']='/bin/bash'
        elif runtime['kind']=='serve':
            app['script']='/home/gandiv/.nvm/versions/node/v22.17.1/lib/node_modules/pm2/lib/API/Serve.js'
            local_env.update(PM2_SERVE_PATH=str(release/'dist'),PM2_SERVE_PORT=str(runtime['port']),PM2_SERVE_SPA='true')
        else:
            app['script']=runtime['script'] if runtime['script'].startswith('/') else str(release/runtime['script'])
        apps.append(app)
    return {'apps':apps}

def healthy(config):
    deadline=time.monotonic()+75
    stable=None
    while time.monotonic()<deadline:
        good=True
        state={e['name']:e['pm2_env'] for e in json.loads(run([PM2,'jlist'],capture=True))}
        for runtime in config['runtimes']:
            if state.get(runtime['name'],{}).get('status')!='online': good=False; break
            try:
                if runtime['kind']=='go' and not runtime.get('health_path'):
                    with socket.create_connection(('127.0.0.1',runtime['port']),timeout=2): pass
                else:
                    with urllib.request.urlopen('http://127.0.0.1:'+str(runtime['port'])+runtime.get('health_path','/'),timeout=5) as response:
                        if response.status >=400: good=False
            except (OSError, urllib.error.URLError): good=False
        if good:
            if not config['runtimes']: return True
            if stable is None: stable=time.monotonic()
            if time.monotonic()-stable>=15: return True
        else: stable=None
        time.sleep(3)
    return False


def restore_environment(root, envfiles):
    for relative,(content,mode) in envfiles.items():
        p=root/relative
        if p.is_file() and p.read_bytes()==content: continue
        p.parent.mkdir(parents=True,exist_ok=True)
        if p.is_symlink(): p.unlink()
        p.write_bytes(content); p.chmod(mode)

def remove(path):
    if path.is_symlink() or path.is_file(): path.unlink()
    elif path.is_dir(): shutil.rmtree(path)

def main():
    global ENV, LOG
    os.umask(0o077)
    parser=argparse.ArgumentParser()
    parser.add_argument('--config',required=True); parser.add_argument('--source',required=True)
    parser.add_argument('--mode',choices=['validate','build','deploy'],required=True)
    opts=parser.parse_args(); config=json.loads(P(opts.config).read_text()); source=P(opts.source).resolve()
    root,branch,sha=validate(config,source)
    node=P('/home/gandiv/.nvm/versions/node')/config['node']/'bin'
    ENV={k:v for k,v in os.environ.items() if k in ('HOME','USER','LANG','LC_ALL','TMPDIR')}
    ENV.update(PATH=str(node)+':/home/gandiv/.nvm/versions/node/v22.17.1/bin:/home/gandiv/.cargo/bin:/usr/local/bin:/usr/bin:/bin:/snap/bin',GOTOOLCHAIN=config.get('go_toolchain','auto'),CI='true',NX_DAEMON='false',PM2_HOME='/home/gandiv/.pm2',NODE_OPTIONS='--max-old-space-size='+str(config.get('heap_mb',3072)))
    if not node.is_dir() or not P(PM2).exists(): raise RuntimeError('Required server tools missing')
    print('Validated '+config['repository']+' branch '+branch+' commit '+sha,flush=True)
    if opts.mode=='validate': return
    state=root/'.deploy'; state.mkdir(mode=0o700,exist_ok=True)
    LOG=state/'build.log'; LOG.touch(mode=0o600,exist_ok=True); LOG.chmod(0o600)
    lockpath=P('/home/gandiv/.local/state/server-deploy/deploy.lock'); lockpath.parent.mkdir(parents=True,exist_ok=True)
    with lockpath.open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        if LOG.stat().st_size>20*1024*1024: LOG.write_text('')
        runid=os.environ.get('GITHUB_RUN_ID','local')+'-'+os.environ.get('GITHUB_RUN_ATTEMPT','1')
        if not re.fullmatch('[A-Za-z0-9-]+',runid): raise ValueError('Invalid run ID')
        backup=state/('backup-'+runid)
        if backup.exists(): raise RuntimeError('Backup already exists; use a new attempt')
        backup.mkdir(mode=0o700)
        existing={e['name']:e['pm2_env'] for e in json.loads(run([PM2,'jlist'],capture=True))}
        names=[r['name'] for r in config['runtimes']]
        active_root=[n for n in names if n in existing and P(existing[n]['pm_cwd']).resolve().is_relative_to(root) and not P(existing[n]['pm_cwd']).resolve().is_relative_to(state)]
        if opts.mode=='build' and (active_root or config['static']):
            raise RuntimeError('Direct build modifies live files; select Build and deploy to restart safely')
        rollback=[]
        for name in names:
            e=existing.get(name)
            if e:
                app={'name':name,'cwd':e['pm_cwd'],'script':e['pm_exec_path'],'args':e.get('args',[]),'interpreter':e.get('exec_interpreter','none'),'env':e.get('env',{})}
                for k in ('namespace','restart_delay','exp_backoff_restart_delay','max_restarts','min_uptime','kill_timeout','listen_timeout','max_memory_restart','node_args'):
                    if e.get(k) is not None: app[k]=e[k]
                rollback.append(app)
        oldfile=backup/'runtime.json'; oldfile.write_text(json.dumps({'apps':rollback})); oldfile.chmod(0o600)
        # Preserve private server configuration even when a repository tracks .env.
        envfiles={}
        for directory,dirs,files in os.walk(root):
            dirs[:]=[d for d in dirs if d not in {'.git','.deploy','node_modules','.next','dist','target','.venv','logs','uploads','storage','data'}]
            for name in files:
                if name.startswith('.env') and not name.endswith(('.example','.sample','.template')):
                    p=P(directory)/name; envfiles[p.relative_to(root)]=(p.read_bytes(),p.stat().st_mode & 0o777)
        for relative,(content,mode) in envfiles.items():
            p=backup/'environment'/relative; p.parent.mkdir(parents=True,exist_ok=True); p.write_bytes(content); p.chmod(0o600)
        outputs=[]
        for name in config['outputs']:
            p=P(name)
            if p.is_absolute() or '..' in p.parts: raise ValueError('Unsafe output path')
            # Next requires the entire .next directory, not only BUILD_ID.
            segment=next((v for v in ('.next','dist') if v in p.parts),None)
            q=P(*p.parts[:p.parts.index(segment)+1]) if segment else p
            if not any(q==x or q.is_relative_to(x) for x in outputs): outputs.append(q)
        moved=[]; restarted=False; building=False
        try:
            # Replace stale/shallow metadata with complete selected-source history.
            # Local metadata is retained privately; application builds still run at root.
            metadata=backup/'fresh-git'
            run(['git','clone','--no-checkout','--no-hardlinks',str(source),str(metadata)])
            run(['git','remote','set-url','origin','https://github.com/'+config['repository']+'.git'],metadata)
            (root/'.git').rename(backup/'previous-git')
            (metadata/'.git').rename(root/'.git')
            exclude=root/'.git/info/exclude'
            with exclude.open('a') as f: f.write('\n/.deploy/\n')
            tracked=run(['git','ls-tree','-r','--name-only',sha],root,capture=True).splitlines()
            if any(P(n).parts[0] in {'.deploy','uploads','storage','data','logs'} for n in tracked): raise RuntimeError('Selected code overlaps server state/data')
            for name in active_root: run([PM2,'stop',name])
            for q in outputs:
                p=root/q
                if p.exists() or p.is_symlink():
                    dest=backup/'outputs'/q; dest.parent.mkdir(parents=True,exist_ok=True); p.rename(dest); moved.append(q)
            run(['git','-c','core.hooksPath=/dev/null','reset','--hard'],root)
            clean=['git','clean','-fd','-e','.deploy/','-e','.env*','-e','node_modules/','-e','uploads/','-e','storage/','-e','data/','-e','logs/','-e','.venv/','-e','target/']
            run(clean,root)
            run(['git','-c','core.hooksPath=/dev/null','checkout','-B',branch,sha],root)
            run(['git','-c','core.hooksPath=/dev/null','reset','--hard',sha],root)
            restore_environment(root,envfiles)
            if run(['git','rev-parse','HEAD'],root,capture=True).strip()!=sha: raise RuntimeError('Project checkout revision mismatch')
            if config.get('source_archive') and not (root/'src').exists():
                with zipfile.ZipFile(root/config['source_archive']) as archive:
                    if sum(i.file_size for i in archive.infolist())>100*1024*1024: raise RuntimeError('Source archive exceeds size limit')
                    for item in archive.infolist():
                        rel=P(item.filename)
                        if rel.is_absolute() or '..' in rel.parts or ((item.external_attr>>16)&0o170000)==0o120000: raise RuntimeError('Unsafe source archive')
                        if not rel.parts or rel.parts[0] in {'.git','.deploy','node_modules','dist','.next','uploads','storage','data','logs'} or rel.name.startswith('.env'): continue
                        archive.extract(item,root)
            print('Building directly in '+str(root)+' at '+sha,flush=True)
            building=True
            build(config,root)
            if config['static']:
                for d,ds,fs in os.walk(root/'dist'):
                    P(d).chmod(0o755)
                    for f in fs: (P(d)/f).chmod(0o644)
            if opts.mode=='deploy':
                newfile=state/'runtime.json'; newfile.write_text(json.dumps(pm2_config(config,root,existing))); newfile.chmod(0o600)
                restarted=True
                for name in names:
                    if name in existing: run([PM2,'delete',name])
                    run([PM2,'start',str(newfile),'--only',name])
                if not healthy(config): raise RuntimeError('Service health check failed')
                if names: run([PM2,'save'])
                current=state/'current'
                if current.is_symlink(): current.unlink()
                atomic_link(root,current)
            receipt={'repository':config['repository'],'branch':branch,'commit':sha,'run':runid,'mode':opts.mode,'time':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'build_directory':str(root),'strategy':'direct'}
            (state/('last-deploy.json' if opts.mode=='deploy' else 'last-build.json')).write_text(json.dumps(receipt,indent=2))
            print('Direct '+opts.mode+' passed: '+sha,flush=True)
            summary=os.environ.get('GITHUB_STEP_SUMMARY')
            if summary:
                with open(summary,'a') as f: f.write('Branch: `'+branch+'`\n\nCommit: `'+sha+'`\n\nBuild directory: `'+str(root)+'`\n\nResult: '+opts.mode+' passed\n')
        except BaseException:
            print('Failed; restoring previous build outputs and targeted services.',flush=True)
            for q in outputs:
                if building or q in moved: remove(root/q)
            for q in moved:
                (root/q).parent.mkdir(parents=True,exist_ok=True); (backup/'outputs'/q).rename(root/q)
            restore_environment(root,envfiles)
            if restarted:
                now={e['name'] for e in json.loads(run([PM2,'jlist'],capture=True))}
                for name in names:
                    if name in now: run([PM2,'delete',name])
                for app in rollback: run([PM2,'start',str(oldfile),'--only',app['name']])
            else:
                for name in active_root: run([PM2,'restart',name])
            if names: run([PM2,'save'])
            raise

if __name__=='__main__':
    def cancelled(signum,frame): raise RuntimeError('Deployment interrupted')
    signal.signal(signal.SIGTERM,cancelled); signal.signal(signal.SIGINT,cancelled)
    try: main()
    except Exception as error: print('::error::'+str(error),file=sys.stderr); sys.exit(1)
