#!/usr/bin/env python3
"""Install isolated staging runtime after bootstrap; do not publish DNS or TLS."""
import os, pathlib, pwd, shutil, subprocess, json, secrets
B=pathlib.Path('/opt/trmm-staging')
S=pathlib.Path('/root/trmm-staging-setup')
a=pwd.getpwnam('trmm-staging')
e=os.environ.copy()
e.update(dict(line.split('=',1) for line in (B/'staging.env').read_text().splitlines() if line and not line.startswith('#')))
def drop():
 os.setgroups([a.pw_gid]);os.setgid(a.pw_gid);os.setuid(a.pw_uid)
def run(args, *, user=False, cwd=None):
 result=subprocess.run(args,env=e,cwd=cwd,preexec_fn=drop if user else None,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
 with (S/'runtime.log').open('a') as f:f.write(result.stdout)
 if result.returncode:raise RuntimeError('Staging setup failed; inspect root-only runtime.log')
 return result.stdout
run(['tar','-xzf',str(S/'trmm-staging-django.tar.gz'),'-C',str(B/'django')])
shutil.copy2(S/'staging_settings.py',B/'django/tacticalrmm/staging_settings.py')
(B/'django/tacticalrmm/local_settings.py').write_text('from .staging_settings import STAGING_BASE\nglobals().update(STAGING_BASE)\n')
run(['chown','-R','root:trmm-staging',str(B/'django')])
run(['chmod','-R','g+rX',str(B/'django')])
shutil.copy2(S/'trmm-staging-go-api',B/'bin/trmm-go');os.chmod(B/'bin/trmm-go',0o755)
# Nginx serves only separately copied public assets.
shutil.copytree('/var/www/rmm/dist','/var/www/rmm2-staging',dirs_exist_ok=True)
pathlib.Path('/var/www/rmm2-staging/env-config.js').write_text('window._env_ = {PROD_URL: "https://api2.q-dt.de"};\n')
run(['chmod','-R','a+rX','/var/www/rmm2-staging'])
run(['systemctl','daemon-reload'])
run(['systemctl','start','trmm-staging-redis','trmm-staging-nats'])
python='/rmm/api/env/bin/python'
run([python,'manage.py','check'],user=True,cwd=B/'django')
run([python,'manage.py','migrate','--noinput'],user=True,cwd=B/'django')
# SQL migrations connect exclusively to the freshly generated staging database.
for name in ['001_mesh_sync.sql','002_script_note_completion.sql']:
 sql=(S/name).read_text()
 code="import os,psycopg; c=psycopg.connect(os.environ['DATABASE_URL'],autocommit=True); c.execute("+repr(sql)+"); c.close()"
 run([python,'-c',code],user=True,cwd=B/'django')
credentials=S/'test-login.json'
if not credentials.exists():
 credentials.write_text(json.dumps({'username':'staging-admin','password':secrets.token_urlsafe(24),'mesh_password':secrets.token_urlsafe(24)}))
 os.chmod(credentials,0o600)
login=json.loads(credentials.read_text())
e['STAGING_ADMIN_PASSWORD']=login['password']
code="""import os
from accounts.models import User
from core.models import CoreSettings
from clients.models import Client, Site
if not User.objects.filter(username='staging-admin').exists():
 User.objects.create_superuser(username='staging-admin',password=os.environ['STAGING_ADMIN_PASSWORD'],email='')
if not CoreSettings.objects.exists():
 CoreSettings.objects.create()
c,_=Client.objects.get_or_create(name='Staging Test')
Site.objects.get_or_create(name='Testlabor',client=c)
print('Fresh staging admin and test client/site prepared')
"""
run([python,'manage.py','shell','-c',code],user=True,cwd=B/'django')
run(['systemctl','start','trmm-staging-django','trmm-staging-go'])
print('Isolated database migrated, staging API services started; credentials in root-only test-login.json')
