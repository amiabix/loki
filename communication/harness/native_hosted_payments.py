from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import hashlib,json,os,re,shlex,subprocess,sys,time,shutil,importlib.util
import native_hosted as hosted
from acceptance_resume import Actions, RpcTunnel, controller_lock, ssh_argv, ensure_manifest
ROOT=hosted.ROOT
TUNNEL=None
POC=Path(__file__).resolve().parents[2]/'core'
sys.path.insert(0,str(POC));from ths import THS
CHAIN=None
LOCAL_PAY=Path(os.environ['LOKI_PAYMENT_BIN']).resolve()
LOCAL_RELAY=LOCAL_PAY.with_name('loki_relay_member');REMOTE_BIN='/var/tmp/loki-hosted-20261014-native-bin/'
PAYROOT=ROOT/'mined-payments'
if not PAYROOT.exists():PAYROOT.mkdir(mode=0o700)
def capture(member,argv,timeout=180,allow_pending=False):
 if member.remote:
  if TUNNEL is not None:TUNNEL.ensure()
  argv=ssh_argv('root@ssf-replica',shlex.join(['runuser','-u',member.user,'--','env','LOKI_RPC=127.0.0.1:47052',*map(str,argv)]))
 result=subprocess.run(argv,env=CHAIN.env(),capture_output=True,timeout=timeout)
 if result.returncode:
  if allow_pending and re.fullmatch(rb'error: waiting for member [1-4] (Commitment|Package|Share); sync relay inbox and retry\n',result.stderr):return None
  hosted.private(PAYROOT/f'failure-{member.count}-{member.slot}-{time.time_ns()}.private',result.stdout[:65536]+result.stderr[:65536]);raise RuntimeError('Native payment command failed; private diagnostics retained')
 return result.stdout
def relay(member,action,*extra):
 return capture(member,[REMOTE_BIN+'loki_relay_member' if member.remote else str(LOCAL_RELAY),action,'--member-root',member.root,'--passphrase-file',member.passfile,'--roster',member.root+'/roster.json',*map(str,extra)])
def pay(member,work,action,*extra,timeout=180,pending=False):
 return capture(member,[REMOTE_BIN+'loki_member_payment' if member.remote else str(LOCAL_PAY),action,member.root,member.passfile,member.root+'/roster.json',work,*map(str,extra)],timeout=timeout,allow_pending=pending)
def parallel(members,callback):
 with ThreadPoolExecutor(max_workers=len(members)) as pool:return list(pool.map(callback,members))
def pump(members,works,attempt,sent,actions):
 for member in members:
  inventory=json.loads(pay(member,works[member.slot],'local-wires'))['wires']
  assert isinstance(inventory,list) and all(re.fullmatch('[0-9a-f]{64}',w) for w in inventory)
  for wire in inventory:
   if wire not in sent:
    actions.run('relay-wire',[attempt,member.slot,wire],lambda:relay(member,'send-signing','--payload-file',works[member.slot]+'/mailbox/'+wire,'--attempt',attempt))
    sent.add(wire)
  relay(member,'upload')
 for member in members:
  for _ in range(32):
   argv=[REMOTE_BIN+'loki_relay_member' if member.remote else str(LOCAL_RELAY),'poll','--member-root',member.root,'--passphrase-file',member.passfile,'--roster',member.root+'/roster.json','--once']
   if member.remote:argv=ssh_argv('root@ssf-replica',shlex.join(['runuser','-u',member.user,'--',*argv]))
   result=subprocess.run(argv,capture_output=True,timeout=180)
   if result.returncode==0:assert result.stdout==b'poll=ok\n';break
   if result.stderr!=b'member_capacity\n':hosted.private(PAYROOT/f'poll-failure-{time.time_ns()}.private',result.stderr);raise RuntimeError('Native poll failed')
   relay(member,'upload')
  else:raise RuntimeError('Bounded native intake did not settle')
  exported=relay(member,'export-signing','--work-dir',works[member.slot],'--attempt',attempt);assert re.fullmatch(rb'exported_signing=\d+\n',exported)
def recipient():
 target=PAYROOT/'recipient';original=Path(os.environ['LOKI_ACCEPTANCE_RECIPIENT']).resolve()
 if not target.exists():
  target.mkdir(mode=0o700);(target/'member-1').mkdir(mode=0o700)
  shutil.copytree(original/'member-1/secrets',target/'member-1/secrets')
  shutil.copyfile(original/'member-1/pass.txt',target/'member-1/pass.txt');os.chmod(target/'member-1/pass.txt',0o600)
  shutil.copyfile(original/'roster.json',target/'roster.json');os.chmod(target/'roster.json',0o600)
  source_hashes={str(p.relative_to(original)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [original/'member-1/pass.txt',original/'roster.json',*sorted((original/'member-1/secrets').glob('*.sealed'))]}
  hosted.private(target/'source-hashes.json',json.dumps(source_hashes,indent=2).encode())
 result=subprocess.run([str(hosted.LOCAL_BIN),'address',str(target/'member-1'),str(target/'member-1/pass.txt')],capture_output=True,timeout=60)
 assert result.returncode==0,'independent recipient address refused'
 return target,result.stdout.decode().strip()
def pair_case(count,pair,destination,receiver):
 case=PAYROOT/f'{count}-{pair}';reportfile=case/'public-payment.json'
 if reportfile.exists():return json.loads(reportfile.read_text())
 if not case.exists():case.mkdir(mode=0o700)
 members=[hosted.Member(count,slot) for slot in range(1,count+1)];creator=members[0]
 proposal_work=case/'proposal'
 if not (proposal_work/'payment.json').exists():pay(creator,str(proposal_work),'prepare',destination,'1000000','native HTTPS acceptance '+pair,pair)
 manifest=json.loads((proposal_work/'payment.json').read_text());attempt=manifest['attempt'];signers=manifest['pair'];works={m.slot:m.root+'/payments/'+attempt for m in members}
 original=(proposal_work/'payment.json').read_bytes();ownwork=Path(works[1])
 ensure_manifest(ownwork/'payment.json',original)
 actions=Actions(case/'actions');identity=[attempt,hashlib.sha256(original).hexdigest()]
 actions.run('proposal',identity,lambda:relay(creator,'send-proposal','--proposal-file',str(ownwork/'payment.json')))
 deadline=time.monotonic()+900
 while True:
  relay(creator,'upload')
  for member in members[1:]:
   relay(member,'poll','--once');relay(member,'import-proposals','--payments-dir',member.root+'/payments');relay(member,'upload')
  if all(m.exists('payments/'+attempt+'/payment.json') for m in members):break
  if time.monotonic()>deadline:raise RuntimeError('Proposal arrival deadline')
 for member in members:
  if member.remote:
   script='from pathlib import Path;import hashlib,stat; p=Path('+repr(works[member.slot]+'/payment.json')+');assert stat.S_IMODE(p.stat().st_mode)==0o600;print(hashlib.sha256(p.read_bytes()).hexdigest())'
   digest=hosted.ssh(shlex.join(['runuser','-u',member.user,'--','python3','-c',script])).decode().strip()
  else:digest=hashlib.sha256((Path(works[member.slot])/'payment.json').read_bytes()).hexdigest()
  assert digest==hashlib.sha256(original).hexdigest(),'changed imported intent'
 sent=set()
 def pump_once():
  if time.monotonic()>deadline:raise RuntimeError('Payment deadline; saved state retained')
  pump(members,works,attempt,sent,actions)
 def ready(member,action,*extra):
  while True:
   value=pay(member,works[member.slot],action,*extra,pending=True)
   if value is not None:return value
   pump_once()
 for slot in signers:
  assert b'commitments published' in actions.run('commit',identity+[slot],lambda:pay(members[slot-1],works[slot],'commit'));pump_once()
 package_owner=members[signers[0]-1];assert b'payment package published' in actions.run('package',identity,lambda:ready(package_owner,'package'));pump_once()
 for slot in signers:
  member=members[slot-1]
  def approve_current():
   review=json.loads(ready(member,'review'))
   expected={key:manifest[key] for key in ('vault','payment','attempt','pair','amount_zat','fee_zat','change_zat','expiry_height','input_nullifiers')};expected['memo_hex']=manifest['memo']
   assert review['authorization_required'] is True and all(review.get(k)==v for k,v in expected.items()),'changed signer review'
   return pay(member,works[slot],'approve-reviewed',review['review_token'])
  assert b'signed locally; approval delivery pending relay storage' in actions.run('approve',identity+[slot],approve_current);pump_once()
 observers=[m for m in members if m.slot not in signers];aggregates=[ready(m,'finish-check') for m in observers]
 assert all(b'aggregate verified' in a for a in aggregates) and len(set(aggregates))==1,'independent aggregate disagreement'
 finisher=next((m for m in observers if not m.remote),observers[0]);remaining=max(1,deadline-time.monotonic())
 finished=actions.run('broadcast',identity+[finisher.slot],lambda:pay(finisher,works[finisher.slot],'finish',timeout=remaining))
 match=re.search(rb'txid=([0-9a-f]{64})',finished);assert match,'no broadcast identity';txid=match[1].decode()
 transaction=CHAIN.rpc('getrawtransaction',[txid,1])
 if transaction.get('confirmations',0)<3:CHAIN.mine(3-transaction.get('confirmations',0))
 for observer in observers:assert b'verified' in pay(observer,works[observer.slot],'verify',txid)
 received=subprocess.run([str(LOCAL_PAY),'receive',str(receiver/'member-1'),str(receiver/'member-1/pass.txt'),str(receiver/'roster.json'),str(proposal_work),txid],env=CHAIN.env(),capture_output=True,timeout=180)
 if received.returncode or b'independently decrypted' not in received.stdout:
  hosted.private(case/'recipient-failure.private',received.stderr[:65536]+received.stdout[:65536]);raise RuntimeError('Independent recipient did not decrypt')
 transaction=CHAIN.rpc('getrawtransaction',[txid,1]);assert transaction['confirmations']>=3
 report={'result':'accepted','source_commit':hosted.SOURCE,'source_tree':hosted.SOURCE_TREE,'policy':f'2-of-{count}','pair':pair,'signers':signers,'independent_finishers':[m.slot for m in observers],'finisher':finisher.slot,'recipient_decrypted':True,'txid':txid,'confirmations':transaction['confirmations'],'block_hash':transaction['blockhash'],'payment':manifest['payment'],'attempt':attempt,'reviewed_manifest_sha256':hashlib.sha256(original).hexdigest(),'aggregate_verification_sha256':hashlib.sha256(aggregates[0]).hexdigest(),'relay_envelopes':len(sent),'transport':'native verified HTTPS','distinct_hosts':2,'private_keys_exported':False,'manual_provisioning':False,'nonce_witness_format':2,'rpc':'owned loopback SSH tunnel, pinned regtest branch 37a5165b'}
 hosted.private(reportfile,json.dumps(report,indent=2).encode());print(json.dumps({'policy':report['policy'],'pair':pair,'result':report['result'],'txid':txid,'evidence':str(reportfile)}),flush=True)
 return report
def main():
 CHAIN.check()
 deadline=time.monotonic()+3600
 while not all((ROOT/f'public-handoff-{count}.json').exists() for count in (3,4)):
  if time.monotonic()>deadline:raise RuntimeError('Separate-host handoff prerequisite deadline')
  time.sleep(1)
 receiver,destination=recipient();reports=[]
 for count,pairs in [(3,('AB','AC','BC')),(4,('AB','AC','AD','BC','BD','CD'))]:
  evidence=json.loads((ROOT/f'public-handoff-{count}.json').read_text());address=evidence['devices'][0]['native']['address'];assert address!=destination
  funding=Actions(PAYROOT/'funding')
  funding.run('fund',[CHAIN.name,address,3],lambda:json.dumps(CHAIN.fund(address,3)).encode(),idempotent=True)
  for pair in pairs:reports.append(pair_case(count,pair,destination,receiver))
 report={'result':'all_both_policy_native_https_payments_accepted','source_commit':hosted.SOURCE,'policies':{'2-of-3':['AB','AC','BC'],'2-of-4':['AB','AC','AD','BC','BD','CD']},'payments':reports,'local_payment_binary_sha256':hashlib.sha256(LOCAL_PAY.read_bytes()).hexdigest()}
 if not (PAYROOT/'public-all-pairs.json').exists():hosted.private(PAYROOT/'public-all-pairs.json',json.dumps(report,indent=2).encode());print(json.dumps({'result':report['result'],'evidence':str(PAYROOT/'public-all-pairs.json')}),flush=True)
def rpc_ready():
 script="import json,urllib.request; r=urllib.request.Request('http://127.0.0.1:47052',data=b'{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getblockchaininfo\",\"params\":[]}',headers={'Content-Type':'application/json'}); d=json.load(urllib.request.urlopen(r,timeout=3))['result']; assert d['chain']=='test' and d['consensus']['nextblock']=='37a5165b'"
 try:
  result=subprocess.run(ssh_argv('root@ssf-replica',shlex.join(['python3','-c',script])),capture_output=True,timeout=12)
  return result.returncode==0
 except subprocess.TimeoutExpired:return False
if __name__=='__main__':
 try:
  CHAIN=THS(os.environ['LOKI_THS_INSTANCE']);CHAIN.check()
  with controller_lock(PAYROOT), RpcTunnel('root@ssf-replica',rpc_ready,PAYROOT) as TUNNEL:main()
 except BaseException:
  import traceback
  hosted.private(PAYROOT/('controller-failure-'+str(time.time_ns())+'.private'),traceback.format_exc().encode());raise RuntimeError('Native HTTPS payment acceptance failed; saved state and private diagnostics retained') from None
