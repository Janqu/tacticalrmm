#!/usr/bin/env python3
"""Configure only the independent MeshCentral inside the dedicated Go test LXC."""
import pathlib,json,subprocess,os,pwd
B=pathlib.Path('/opt/trmm')
a=pwd.getpwnam('trmm')
credentials=json.loads(pathlib.Path('/root/trmm-staging-mesh.json').read_text())
config={'settings':{'cert':'mesh2.q-dt.de','WANonly':True,'port':14430,'portBind':'127.0.0.1','aliasPort':443,'redirPort':0,'mpsPort':0,'allowLoginToken':True,'allowFraming':True,'tlsOffload':'127.0.0.1','autoBackup':False,'agentCoreDump':False},'domains':{'':{'title':'RMM2 Test','title2':'Isolated Mesh','newAccounts':False,'certUrl':'https://mesh2.q-dt.de/','cookieIpCheck':False}}}
p=B/'mesh-data/config.json';p.write_text(json.dumps(config,indent=2));os.chown(p,a.pw_uid,a.pw_gid);os.chmod(p,0o600)
h=pathlib.Path('/etc/hosts');s=h.read_text()
line='192.168.1.85 api2.q-dt.de rmm2.q-dt.de mesh2.q-dt.de'
if line not in s:h.write_text(s+'\n'+line+'\n')
base=['runuser','-u','trmm','--','/usr/bin/node','/opt/trmm/mesh/node_modules/meshcentral','--datapath','/opt/trmm/mesh-data','--filespath','/opt/trmm/mesh-files']
marker=B/'mesh-data/.test-admin-created'
if not marker.exists():
 for tail in [['--createaccount',credentials['username'],'--pass',credentials['password']],['--adminaccount',credentials['username']]]:
  result=subprocess.run(base+tail,cwd=B/'mesh',capture_output=True,text=True,timeout=120)
  with pathlib.Path('/root/trmm-setup/mesh-setup.log').open('a') as f:f.write(result.stdout+result.stderr)
  if result.returncode or 'Done.' not in result.stdout:raise RuntimeError('Mesh account setup failed; inspect root-only log')
 marker.touch();os.chmod(marker,0o600)
unit='[Unit]\nDescription=Independent RMM2 MeshCentral\nAfter=network.target nginx.service\n[Service]\nUser=trmm\nGroup=trmm\nWorkingDirectory=/opt/trmm/mesh\nExecStart=/usr/bin/node --max-old-space-size=512 /opt/trmm/mesh/node_modules/meshcentral --datapath /opt/trmm/mesh-data --filespath /opt/trmm/mesh-files\nRestart=on-failure\nRestartSec=5\nMemoryMax=768M\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectHome=yes\nUMask=0027\n[Install]\nWantedBy=multi-user.target\n'
pathlib.Path('/etc/systemd/system/trmm-mesh.service').write_text(unit)
subprocess.run(['systemctl','daemon-reload'],check=True)
subprocess.run(['systemctl','enable','--now','trmm-go','trmm-mesh','nginx','redis-server','nats-server','postgresql'],check=True)
print('Independent Mesh account and service installed; secrets remain root-only.')
