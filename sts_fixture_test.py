"""Original frame/state observations, explicit invalid-point policy, integer codec."""
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile

root=pathlib.Path(__file__).resolve().parent/'sts-fixtures'
if not root.exists():root=pathlib.Path(__file__).resolve().parents[3]/'migration/fixtures/msgsync-sts'
manifest=json.loads((root/'manifest.json').read_text())
for name,digest in manifest['files_sha256'].items():assert hashlib.sha256((root/name).read_bytes()).hexdigest()==digest
commands=(root/'commands.txt').read_bytes();original=(root/'expected.txt').read_bytes()
expected=original.decode().splitlines();lines=commands.decode().splitlines()
policy=json.loads((root/'native-policy.json').read_text())
for position,row in policy['observation_overrides'].items():
    index=int(position);assert hashlib.sha256(lines[index].encode()).hexdigest()==row['command_sha256']
    assert expected[index]==row['original'];expected[index]=row['required_native']
integers=json.loads((root/'integers.json').read_text())
commands+=b''.join(('INTEGER '+value['unsigned']+'\n').encode() for value in integers)
expected+=['INTEGER '+value['java_integer'] for value in integers]
work=pathlib.Path(tempfile.mkdtemp(prefix='biglybtc-sts-fixtures-'));path=work/'commands.txt';path.write_bytes(commands);inode=path.stat().st_ino
result=subprocess.run([sys.argv[1],str(path)],check=True,capture_output=True,timeout=120)
(work/'native.txt').write_bytes(result.stdout);(work/'stderr.txt').write_bytes(result.stderr)
actual=result.stdout.decode().splitlines();assert len(actual)==len(expected),(work,len(actual),len(expected))
for i,(native,java) in enumerate(zip(actual,expected)):assert native==java,(work,i,commands.splitlines()[i],native,java)
assert path.read_bytes()==commands and path.stat().st_ino==inode
print('PASS original STS frames:',manifest['cases'],'cases,',manifest['observations'],'observations,',len(integers),
    'integer vectors; explicit invalid-point rejection rows',len(policy['observation_overrides']),work)
