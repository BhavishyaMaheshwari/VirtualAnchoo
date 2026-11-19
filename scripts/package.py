"""Create a portable source ZIP with built assets and a SHA-256 file manifest.

Run checks/build first (scripts/test.sh). Dependencies, runtime captures, local
settings, credentials, caches and Git internals are deliberately excluded.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
EXCLUDE = {'.git','.venv','.venv-lab','node_modules','data','.run','__pycache__','.pytest_cache','.ruff_cache','artifacts','.cache'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=ROOT.parent/'NetScope.zip')
    args=parser.parse_args()
    output=args.output.resolve()
    if not (ROOT/'frontend/dist/index.html').exists():
        parser.error('Build the frontend before packaging: npm --prefix frontend run build')
    files=[]
    for path in sorted(ROOT.rglob('*')):
        rel=path.relative_to(ROOT)
        if set(rel.parts)&EXCLUDE or path.is_symlink() or not path.is_file(): continue
        if path.resolve()==output or path.suffix in {'.zip','.pyc','.tsbuildinfo','.sqlite3','.pcap','.pcapng'}: continue
        if path.name=='.env' or path.name.startswith('.env.'): continue
        files.append((path,rel))
    output.parent.mkdir(parents=True,exist_ok=True)
    manifest=[]
    def add(archive, name, data, executable=False):
        info=ZipInfo('netscope/'+name,date_time=(2026,1,1,0,0,0))
        info.compress_type=ZIP_DEFLATED
        info.external_attr=(0o100755 if executable else 0o100644)<<16
        archive.writestr(info,data)
    with ZipFile(output,'w',compression=ZIP_DEFLATED,compresslevel=9) as archive:
        for path,rel in files:
            data=path.read_bytes()
            manifest.append(f'{sha256(data).hexdigest()}  {rel.as_posix()}')
            add(archive,rel.as_posix(),data,path.suffix=='.sh')
        add(archive,'MANIFEST.sha256',('\n'.join(manifest)+'\n').encode())
    digest=sha256(output.read_bytes()).hexdigest()
    output.with_suffix('.zip.sha256').write_text(f'{digest}  {output.name}\n')
    with ZipFile(output) as archive:
        assert archive.testzip() is None
    print(f'{output}\n{len(files)} files plus manifest; {output.stat().st_size:,} bytes\nSHA256 {digest}')

if __name__=='__main__': main()
