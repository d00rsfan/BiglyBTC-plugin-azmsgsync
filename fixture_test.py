"""Replay original key derivation and Java/vendored-BC envelope observations."""
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
base = pathlib.Path(__file__).resolve().parent
root = base / 'fixtures'
if not (root / 'manifest.json').is_file():
    root = (base / '../../../migration/fixtures/msgsync-envelope').resolve()
manifest = json.loads((root / 'manifest.json').read_text())
commands, expected = (root / 'commands.txt').read_bytes(), (root / 'expected.txt').read_bytes()
assert hashlib.sha256(commands).hexdigest() == manifest['commands_sha256']
assert hashlib.sha256(expected).hexdigest() == manifest['expected_sha256']
work = pathlib.Path(tempfile.mkdtemp(prefix='biglybtc-msgsync-envelope-replay-'))
path = work / 'commands.txt'; path.write_bytes(commands); inode = path.stat().st_ino
result = subprocess.run([sys.argv[1], str(path)], check=True, capture_output=True, timeout=60)
(work / 'native.txt').write_bytes(result.stdout); (work / 'stderr.txt').write_bytes(result.stderr)
actual, original = result.stdout.splitlines(), expected.splitlines()
assert len(actual) == len(original)
for i, (a, b) in enumerate(zip(actual, original)):
    assert a == b, (work, i, a[:140], b[:140])
assert path.read_bytes() == commands and path.stat().st_ino == inode
print('PASS original message-sync envelopes:', manifest['observations'], 'observations;', work)
