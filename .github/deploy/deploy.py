#!/usr/bin/env python3
"""Build an immutable branch release and activate only this project's services."""
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
    for runtime in config['runtimes']:
        if runtime['cwd'] != '.' and ('..' in P(runtime['cwd']).parts or P(runtime['cwd']).is_absolute()):
            raise ValueError('Invalid runtime cwd')
    return root, branch, sha

def link_local_config(root, release):
    # Server-owned env and mutable data are never committed or uploaded.
    for directory, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in {'.git','.deploy','node_modules','.next','dist','target','.venv','logs','uploads','storage','data'}]
        for name in files:
            if name in {'.env','.env.local','.env.production','.env.production.local'}:
                src=P(directory)/name; dst=release/src.relative_to(root)
                dst.parent.mkdir(parents=True,exist_ok=True)
                if dst.exists() or dst.is_symlink(): dst.unlink()
                dst.symlink_to(src)
    for name in ('uploads','storage','data','logs'):
        if (root/name).is_dir():
            dst=release/name
            if dst.exists(): shutil.rmtree(dst)
            dst.symlink_to(root/name)

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
            wrapper=release/('start-'+name+'.sh')
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

def activate(config, root, release):
    state=root/'.deploy'; current=state/'current'
    previous=current.resolve() if current.exists() else root
    # Capture only targeted processes for rollback, in a protected local file.
    existing={e['name']:e['pm2_env'] for e in json.loads(run([PM2,'jlist'],capture=True))}
    names=[r['name'] for r in config['runtimes']]
    rollback=[]
    for name in names:
        e=existing.get(name)
        if e:
            rollback.append({'name':name,'cwd':e['pm_cwd'],'script':e['pm_exec_path'],
                'args':e.get('args',[]),'interpreter':e.get('exec_interpreter','none'),
                'env':e.get('env',{}),'restart_delay':e.get('restart_delay',3000)})
            rollback[-1].update({key:e[key] for key in ('namespace','exp_backoff_restart_delay','max_restarts','min_uptime','kill_timeout','listen_timeout','max_memory_restart','node_args') if e.get(key) is not None})
    oldfile=state/'rollback-runtime.json'; oldfile.write_text(json.dumps({'apps':rollback})); oldfile.chmod(0o600)
    newfile=state/'runtime.json'; newfile.write_text(json.dumps(pm2_config(config,release,existing))); newfile.chmod(0o600)
    static=root/'dist'; initial=state/'initial-dist'
    if config['static'] and not static.is_symlink():
        if initial.exists(): raise RuntimeError('Unexpected initial-dist collision')
        if static.exists(): static.rename(initial)
    try:
        if config['static']: atomic_link(release/'dist',static)
        for name in names:
            if name in existing: run([PM2,'delete',name])
            run([PM2,'start',str(newfile),'--only',name])
        if not healthy(config): raise RuntimeError('Service health check failed')
        if names: run([PM2,'save'])
        atomic_link(release,current)
    except Exception:
        print('Activation failed. Restoring previous runtime.',flush=True)
        if previous==root:
            if current.is_symlink(): current.unlink()
        else: atomic_link(previous,current)
        if config['static']:
            if previous==root and initial.exists():
                if static.is_symlink(): static.unlink()
                initial.rename(static)
            else: atomic_link(previous/'dist',static)
        now={e['name'] for e in json.loads(run([PM2,'jlist'],capture=True))}
        for name in names:
            if name in now: run([PM2,'delete',name])
        for app in rollback: run([PM2,'start',str(oldfile),'--only',app['name']])
        if names: run([PM2,'save'])
        raise
    # Keep current and previous for rollback. Delete only our own older releases.
    keep={release.resolve(),previous.resolve()}
    for candidate in (state/'releases').iterdir():
        if candidate.is_dir() and not candidate.is_symlink() and candidate.resolve() not in keep:
            shutil.rmtree(candidate)
    return previous

def main():
    global ENV, LOG
    os.umask(0o077)
    args=argparse.ArgumentParser(); args.add_argument('--config',required=True); args.add_argument('--source',required=True); args.add_argument('--mode',choices=['validate','build','deploy'],required=True)
    opts=args.parse_args(); config=json.loads(P(opts.config).read_text()); source=P(opts.source).resolve()
    root, branch, sha=validate(config,source)
    node=P('/home/gandiv/.nvm/versions/node')/config['node']/'bin'
    ENV={k:v for k,v in os.environ.items() if k in ('HOME','USER','LANG','LC_ALL','TMPDIR')}
    ENV.update(PATH=str(node)+':/home/gandiv/.nvm/versions/node/v22.17.1/bin:/home/gandiv/.cargo/bin:/usr/local/bin:/usr/bin:/bin:/snap/bin', GOTOOLCHAIN=config.get('go_toolchain','auto'), CI='true', NX_DAEMON='false', PM2_HOME='/home/gandiv/.pm2', NODE_OPTIONS='--max-old-space-size='+str(config.get('heap_mb',3072)))
    if not node.is_dir() or not P(PM2).exists(): raise RuntimeError('Required server tools missing')
    print('Validated '+config['repository']+' branch '+branch+' commit '+sha,flush=True)
    if opts.mode=='validate': return
    exclude=P(run(['git','rev-parse','--git-path','info/exclude'],root,capture=True).strip())
    if not exclude.is_absolute(): exclude=root/exclude
    exclude.parent.mkdir(parents=True,exist_ok=True)
    if '/.deploy/' not in exclude.read_text().splitlines():
        with exclude.open('a') as f: f.write('\n/.deploy/\n')
    state=root/'.deploy'; state.mkdir(mode=0o700,exist_ok=True); (state/'releases').mkdir(exist_ok=True)
    LOG=state/'build.log'; LOG.touch(mode=0o600,exist_ok=True); LOG.chmod(0o600)
    # Global lock bounds memory use across repository-specific runner instances.
    lockpath=P('/home/gandiv/.local/state/server-deploy/deploy.lock')
    lockpath.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    with lockpath.open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        if LOG.stat().st_size>20*1024*1024: LOG.write_text('')
        runid=os.environ.get('GITHUB_RUN_ID','local')+'-'+os.environ.get('GITHUB_RUN_ATTEMPT','1')
        if not re.fullmatch('[A-Za-z0-9-]+',runid): raise ValueError('Invalid run ID')
        release=state/'releases'/(sha[:12]+'-'+runid)
        if release.exists(): raise RuntimeError('Release already exists; rerun with a new attempt')
        release.mkdir(mode=0o755)
        try:
            run(['git','clone','--no-local','--no-checkout',str(source),str(release)])
            run(['git','read-tree',sha],release)
            run(['git','remote','set-url','origin','https://github.com/'+config['repository']+'.git'],release)
            run(['rsync','-a','--exclude=.git','--exclude=.deploy','--exclude=node_modules','--exclude=.next','--exclude=dist','--exclude=target','--exclude=.venv','--exclude=.env*','--exclude=/logs/','--exclude=/uploads/','--exclude=/storage/','--exclude=/data/',str(source)+'/',str(release)+'/'])
            if config.get('source_archive') and not (release/'src').exists():
                with zipfile.ZipFile(release/config['source_archive']) as archive:
                    if sum(i.file_size for i in archive.infolist())>100*1024*1024: raise RuntimeError('Source archive exceeds size limit')
                    for item in archive.infolist():
                        relative=P(item.filename)
                        if relative.is_absolute() or '..' in relative.parts or ((item.external_attr>>16)&0o170000)==0o120000: raise RuntimeError('Unsafe source archive entry')
                        if not relative.parts or relative.parts[0] in {'.git','.deploy','node_modules','dist','.next'} or relative.name.startswith('.env'): continue
                        archive.extract(item,release)
            link_local_config(root,release)
            print('Building selected branch; output stays in protected server log.',flush=True)
            build(config,release)
            # Static files must remain readable by nginx while env/backend stay private.
            if config['static']:
                state.chmod(0o755); (state/'releases').chmod(0o755)
                for d,ds,fs in os.walk(release/'dist'):
                    P(d).chmod(0o755)
                    for f in fs: (P(d)/f).chmod(0o644)
            receipt={'repository':config['repository'],'branch':branch,'commit':sha,'run':runid,'mode':opts.mode,'time':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())}
            if opts.mode=='deploy':
                receipt['previous']=str(activate(config,root,release))
                (state/'last-deploy.json').write_text(json.dumps(receipt,indent=2))
                print(('Services passed health checks: ' if config['runtimes'] else 'Static release activated: ' if config['static'] else 'Built release published; no runtime configured: ')+sha,flush=True)
            else: print('Build passed. Running service unchanged.',flush=True)
            (release/'deployment-receipt.json').write_text(json.dumps(receipt,indent=2))
            if opts.mode=='build':
                candidates=sorted((state/'releases').iterdir(),key=lambda p:p.stat().st_mtime,reverse=True)
                keep={p.resolve() for p in candidates[:2]}
                if (state/'current').exists(): keep.add((state/'current').resolve())
                if (state/'last-deploy.json').exists(): keep.add(P(json.loads((state/'last-deploy.json').read_text())['previous']).resolve())
                for candidate in candidates:
                    if candidate.is_dir() and not candidate.is_symlink() and candidate.resolve() not in keep: shutil.rmtree(candidate)
            summary=os.environ.get('GITHUB_STEP_SUMMARY')
            if summary:
                with open(summary,'a') as f: f.write('Branch: `'+branch+'`\n\nCommit: `'+sha+'`\n\nResult: '+opts.mode+' passed\n')
        except Exception:
            # A failed release is never the active target.
            current=state/'current'
            if not current.exists() or current.resolve()!=release.resolve(): shutil.rmtree(release)
            raise

if __name__=='__main__':
    def cancelled(signum, frame): raise RuntimeError('Deployment interrupted')
    signal.signal(signal.SIGTERM,cancelled)
    signal.signal(signal.SIGINT,cancelled)
    try: main()
    except Exception as error:
        print('::error::'+str(error),file=sys.stderr); sys.exit(1)
