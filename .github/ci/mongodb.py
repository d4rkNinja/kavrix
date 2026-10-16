#!/home/gandiv/.local/share/ci-tools/python/bin/python
"""Disposable loopback-only CI replica set; never opens production databases."""
import os,pathlib,subprocess,sys,time,socket,signal,json,shutil
from pymongo import MongoClient
TOOLS=pathlib.Path('/home/gandiv/.local/share/ci-tools')
MONGODB_SHA256='7d67c164da52d31ec144778b40ec9ab6bdaa0c250be020b44dacdcf91a7de3c0'
import hashlib
if hashlib.file_digest((TOOLS/'mongodb-8.0.16.tgz').open('rb'),'sha256').hexdigest()!=MONGODB_SHA256:raise SystemExit('MongoDB distribution checksum mismatch')
if not os.environ.get('RUNNER_TEMP'):raise SystemExit('RUNNER_TEMP is required')
base=pathlib.Path(os.environ['RUNNER_TEMP']).resolve()
state=base/('mongo-'+os.environ.get('GITHUB_RUN_ID','local')+'-'+os.environ.get('GITHUB_RUN_ATTEMPT','1')+'-'+os.environ.get('GITHUB_JOB','test'))
if state.parent!=base:raise SystemExit('Invalid CI state directory')
port=int(os.environ.get('CI_MONGO_PORT','37017'))
uri=f'mongodb://127.0.0.1:{port}/?replicaSet=rs0'
if sys.argv[1]=='start':
 with socket.socket() as probe:probe.bind(('127.0.0.1',port))
 state.mkdir(mode=0o700,parents=True,exist_ok=False)
 (state/'db').mkdir(mode=0o700)
 subprocess.run([str(TOOLS/'mongodb-8.0.16/bin/mongod'),'--dbpath',str(state/'db'),'--bind_ip','127.0.0.1','--port',str(port),'--replSet','rs0','--wiredTigerCacheSizeGB','0.25','--fork','--logpath',str(state/'mongo.log'),'--pidfilepath',str(state/'pid')],check=True,stdout=subprocess.DEVNULL)
 client=MongoClient(f'mongodb://127.0.0.1:{port}/?directConnection=true',serverSelectionTimeoutMS=3000)
 client.admin.command('replSetInitiate',{'_id':'rs0','members':[{'_id':0,'host':f'127.0.0.1:{port}'}]})
 for attempt in range(60):
  try:
   if client.admin.command('hello').get('isWritablePrimary'):break
  except Exception:pass
  time.sleep(1)
 else:raise SystemExit('CI MongoDB did not become primary')
 client.close()
 if os.environ.get('GITHUB_ENV'):
  with open(os.environ['GITHUB_ENV'],'a') as f:f.write('MONGO_TEST_URI='+uri+'\nKAVRIX_MONGO_PROBE_TEST_URI='+uri+'\n')
 print('Temporary MongoDB 8.0.16 replica set ready on loopback port',port)
elif sys.argv[1]=='stop':
 if not state.exists():sys.exit(0)
 pidfile=state/'pid'
 if pidfile.exists():
  pid=int(pidfile.read_text()); proc=pathlib.Path('/proc')/str(pid)
  try:cmdline=(proc/'cmdline').read_bytes().split(b'\0')
  except FileNotFoundError:cmdline=[]
  if cmdline and str(state/'db').encode() not in cmdline:raise SystemExit('Refusing to stop unrelated process')
  if cmdline:
   os.kill(pid,signal.SIGTERM)
   for _ in range(100):
    if not proc.exists():break
    time.sleep(.1)
   else:raise SystemExit('CI MongoDB did not stop')
 shutil.rmtree(state)
 print('Temporary CI MongoDB stopped and data removed')
else:raise SystemExit('Use start or stop')
