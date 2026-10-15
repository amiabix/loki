from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import base64,hashlib,json,os,platform,shlex,subprocess,time,sys
from acceptance_resume import agreement_needed, backup_actions, controller_lock, ssh_argv, TERMINAL, write_new
ROOT=Path(os.environ['LOKI_ACCEPTANCE_ROOT']).resolve()
LOCAL_BIN=Path(os.environ['LOKI_SETUP_BIN']).resolve()
REMOTE_BIN='/var/tmp/loki-hosted-20261014-native-bin/loki_setup_member'
REMOTE_OPS='/var/tmp/loki-hosted-20261014-acceptance/operator'
CONFIG=json.loads((ROOT/'public-operator.json').read_text());KEY=CONFIG['trusted_key']
OWNER=json.loads((ROOT/'owner.json').read_text());SOURCE=OWNER['source_commit']
SOURCE_TREE=os.environ['LOKI_SOURCE_TREE']
assert OWNER['purpose']=='native separate-host HTTPS acceptance'
assert ROOT.is_dir() and ROOT.stat().st_mode & 0o777 == 0o700
def private(path,raw):
 write_new(path,raw)
def ssh(command,*,input=None,timeout=180):
 result=subprocess.run(ssh_argv('root@ssf-replica',command),input=input,capture_output=True,timeout=timeout)
 if result.returncode:
  name=ROOT/('ssh-failure-'+str(time.time_ns())+'.private');private(name,result.stdout[:65536]+result.stderr[:65536]);raise RuntimeError('SSH operation failed; private diagnostics retained')
 return result.stdout
class Member:
 def __init__(self,count,slot):
  self.count=count;self.slot=slot;self.remote=slot!=1
  self.root=f'/var/tmp/loki-hosted-20261014-member-{count}-{slot}' if self.remote else str(ROOT/f'member-{count}-1')
  self.user=f'loki-acceptance-261014-{slot}' if self.remote else None
  self.passfile=self.root+'/passphrase'
 def command(self,command,*args,allow_failure=False):
  argv=[REMOTE_BIN if self.remote else str(LOCAL_BIN),command,*map(str,args)]
  if self.remote:argv=ssh_argv('root@ssf-replica',shlex.join(['runuser','-u',self.user,'--',*argv]))
  result=subprocess.run(argv,capture_output=True,timeout=180)
  if result.returncode and not allow_failure:
   private(ROOT/f'failure-{self.count}-{self.slot}-{time.time_ns()}.private',result.stdout[:65536]+result.stderr[:65536]);raise RuntimeError(f'Native {command} failed for {self.count}/{self.slot}; diagnostics retained')
  if result.returncode:return None
  return json.loads(result.stdout)
 def step(self):return self.command('setup-step',self.root,self.passfile)
 def status(self):return self.command('setup-status',self.root)
 def exists(self,name):
  if self.remote:return ssh(shlex.join(['runuser','-u',self.user,'--','python3','-c',f'import pathlib;print(pathlib.Path({(self.root+"/"+name)!r}).is_file())'])).strip()==b'True'
  return (Path(self.root)/name).is_file()
 def backup(self):
  if self.exists('checked-words'):return
  if self.remote:
   script='import os,subprocess; p='+repr(self.root+'/checked-words')+'; r=subprocess.run('+repr([REMOTE_BIN,'setup-backup-create',self.root,self.passfile,self.root+'/provisional-card'])+',capture_output=True,timeout=180); assert r.returncode==0; fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600); os.write(fd,r.stdout); os.fsync(fd); os.close(fd)'
   ssh(shlex.join(['runuser','-u',self.user,'--','python3','-c',script]))
  else:
   result=subprocess.run([str(LOCAL_BIN),'setup-backup-create',self.root,self.passfile,self.root+'/provisional-card'],capture_output=True,timeout=180)
   if result.returncode:private(ROOT/f'backup-failure-{self.count}.private',result.stderr);raise RuntimeError('Local backup creation failed')
   private(Path(self.root)/'checked-words',result.stdout)
 def finish_backup(self):
  if not self.exists('final-card/vault.card'):self.command('setup-backup-finalize',self.root,self.passfile,self.root+'/provisional-card',self.root+'/final-card',self.root+'/checked-words')
def group(members,callback):
 with ThreadPoolExecutor(max_workers=len(members)) as pool:return list(pool.map(callback,members))
def drive(members,done,label,timeout=1200):
 deadline=time.monotonic()+timeout;rounds=0;last=None
 while True:
  states=group(members,lambda m:m.step());rounds+=1
  phases=[s['phase'] for s in states]
  if phases!=last:print(json.dumps({'policy':f'2-of-{len(members)}','stage':label,'round':rounds,'phases':phases}),flush=True);last=phases
  if any(p in TERMINAL for p in phases):raise RuntimeError('Native ceremony terminated; saved state retained')
  if done(states):return states
  if time.monotonic()>deadline:raise RuntimeError('Native ceremony deadline; saved state retained')
  time.sleep(.15)
def policy(count):
 report_path=ROOT/f'public-handoff-{count}.json'
 if report_path.exists():return json.loads(report_path.read_text())
 members=[Member(count,slot) for slot in range(1,count+1)];creator=members[0];local=Path(creator.root)
 if not local.exists():
  local.mkdir(mode=0o700);private(local/'passphrase',os.urandom(32).hex().encode());private(local/'operator.cbor',base64.b64decode(CONFIG['bundle_b64']))
 if not (local/'secrets/identity.sealed').exists():creator.command('identity',creator.root,'1',creator.passfile)
 if not (local/'secrets/hosted-context.sealed').exists():
  identity=creator.command('identity-public',creator.root,creator.passfile)
  grant=local/'enrollment.grant'
  if not grant.exists():
   raise RuntimeError('Saved enrollment grant missing; reconcile original grant before provisioning')
  creator.command('setup-create',creator.root,creator.passfile,local/'operator.cbor',grant,f'2-of-{count}','--operator-key',KEY)
 deadline=time.monotonic()+180
 while True:
  state=creator.step()
  if state['phase'] not in ('admission_pending','provisioning'):break
  if time.monotonic()>deadline:raise RuntimeError('Creator admission/provision deadline')
 print(json.dumps({'policy':f'2-of-{count}','stage':'creator-provisioned','phase':state['phase']}),flush=True)
 for peer in members[1:]:
  if peer.exists('secrets/hosted-context.sealed'):
   continue
  invite=local/f'invite-{peer.slot}.private'
  if not invite.exists():
   if state['phase'] not in ('invites_ready','waiting_joins'):
    raise RuntimeError('Missing invitation after provisioning; reconcile saved invitation')
   creator.command('setup-invite',creator.root,creator.passfile,str(peer.slot),invite)
  if not peer.exists('invitation.private'):
   command='set -eu; umask 077; '+shlex.join(['tee',peer.root+'/invitation.private'])+' >/dev/null; '+shlex.join(['chown',peer.user+':'+peer.user,peer.root+'/invitation.private'])
   ssh(command,input=invite.read_bytes())
  peer.command('setup-join',peer.root,peer.passfile,peer.root+'/invitation.private',peer.root+'/operator.cbor','--operator-key',KEY)
  peer.step()
 print(json.dumps({'policy':f'2-of-{count}','stage':'saved-peer-contexts-preserved'}),flush=True)
 fingerprints=None
 def ready(states):
  nonlocal fingerprints
  proposed=group(members,lambda m:m.command('setup-info',m.root,m.passfile))
  if any(p.get('fingerprint') is None for p in proposed):return False
  values=[p['fingerprint'] for p in proposed];assert len(set(values))==1,'distinct signer fingerprints';fingerprints=values;return True
 drive(members,ready,'fingerprint-arrival')
 fingerprint=fingerprints[0]
 for member in members:
  if agreement_needed(member.status(),fingerprint):member.command('setup-agree',member.root,member.passfile,fingerprint)
 drive(members,lambda states:all(s['phase'] in ('awaiting_backups','certified','payment_handoff','active') for s in states),'native-dkg-certificate')
 for member in members:
  actions=backup_actions(member.status(),words=member.exists('checked-words'),final_card=member.exists('final-card/vault.card'))
  if 'create' in actions:member.backup()
  if 'verify' in actions:member.command('setup-backup-verify',member.root,member.passfile,member.root+'/provisional-card',member.root+'/checked-words')
 drive(members,lambda states:all(s['phase'] in ('certified','payment_handoff','active') for s in states),'all-backup-receipts')
 group(members,lambda m:m.finish_backup())
 drive(members,lambda states:all(s['phase']=='active' and s['handoff']=='ready' for s in states),'scoped-configuration-signed-activation')
 native=group(members,lambda m:m.command('setup-evidence',m.root,m.passfile))
 for field in ('policy','vault','fingerprint','address','group_ak','configuration_digest','relays'):
  assert all(e[field]==native[0][field] for e in native),'member evidence mismatch '+field
 assert all(e['handoff']=='ready' and e['development'] is False for e in native)
 assert {e['own_slot'] for e in native}==set(range(1,count+1))
 remote_manifest=json.loads(ssh('cat /var/tmp/loki-hosted-20261014-native-bin/updated-base-binary-manifest.json'))
 remote_hostname=ssh('hostname').decode().strip();devices=[]
 for member,evidence in zip(members,native):
  host=remote_hostname if member.remote else platform.node()
  binary_hash=remote_manifest['files']['loki_setup_member']['sha256'] if member.remote else hashlib.sha256(LOCAL_BIN.read_bytes()).hexdigest()
  device={'kind':'operator_collected_device','host_id':hashlib.sha256(host.encode()).hexdigest(),'native_binary_sha256':binary_hash,'native':evidence}
  path=ROOT/f'public-device-{count}-{member.slot}.json'
  if path.exists():assert json.loads(path.read_text())==device,'saved device evidence changed'
  else:private(path,json.dumps(device,indent=2).encode())
  devices.append(device)
 report={'result':'native_separate_host_signed_handoff_accepted','policy':f'2-of-{count}','source_commit':SOURCE,'source_tree':SOURCE_TREE,'distinct_hosts':len({d['host_id'] for d in devices}),'creator_offline_during_independent_arrival':True,'private_keys_created_on_own_host':True,'shared_communication_folder':False,'configuration_sha256':CONFIG['configuration_sha256'],'fingerprint':fingerprint,'devices':devices,'linux_compiler':remote_manifest['compiler'],'mac_compiler':'rustc 1.91.0 (f8297e351 2025-10-28)','establishes_mined_payment':False}
 assert report['distinct_hosts']>=2
 private(report_path,json.dumps(report,indent=2).encode());print(json.dumps({'policy':report['policy'],'result':report['result'],'evidence':str(report_path)}),flush=True)
 return report
if __name__=='__main__':
 try:
  with controller_lock(ROOT):reports=[policy(count) for count in (3,4)]
  print(json.dumps({'result':'both_policy_native_https_handoffs_accepted','policies':[r['policy'] for r in reports]}),flush=True)
 except BaseException:
  import traceback
  private(ROOT/('controller-failure-'+str(time.time_ns())+'.private'),traceback.format_exc().encode());raise RuntimeError('Native HTTPS acceptance failed; state and private diagnostics retained') from None
