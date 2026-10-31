"""Bounded whole-file integrity/encoding audit, never silently strips binary data."""
from pathlib import Path
import codecs
import hashlib
from .common import utcnow


def audit_file(path,check=None):
    path=Path(path).resolve();before=path.stat();digest=hashlib.sha256()
    decoder=codecs.getincrementaldecoder('utf-8')();offset=0;first_invalid=None
    with path.open('rb') as f:
        while block:=f.read(4*1024*1024):
            if check:check()
            digest.update(block)
            if first_invalid is None:
                carry=len(decoder.getstate()[0])
                try:decoder.decode(block,final=False)
                except UnicodeDecodeError as exc:first_invalid=offset-carry+exc.start
                nul=block.find(b'\0')
                if nul>=0:first_invalid=min(first_invalid if first_invalid is not None else offset+nul,offset+nul)
            offset+=len(block)
        if first_invalid is None:
            try:decoder.decode(b'',final=True)
            except UnicodeDecodeError:first_invalid=max(0,offset-len(decoder.getstate()[0]))
        prefix=before.st_size
        if first_invalid is not None:
            # Find the preceding record boundary in bounded backward blocks.
            pos=first_invalid;prefix=0
            while pos>0:
                start=max(0,pos-1024*1024);f.seek(start);chunk=f.read(pos-start)
                end=chunk.rfind(b'\n')
                if end>=0:prefix=start+end+1;break
                pos=start
    after=path.stat()
    if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns):raise ValueError('Input changed during audit')
    return {'source_file':str(path),'size_bytes':before.st_size,'mtime_ns':before.st_mtime_ns,
            'sha256':digest.hexdigest(),'first_invalid_byte':first_invalid,
            'processable_prefix_bytes':prefix,'excluded_tail_bytes':before.st_size-prefix,
            'encoding_status':'utf8' if first_invalid is None else 'unsupported_binary_tail',
            'audited_at':utcnow(),'limitations':'UTF-8 validity does not establish valid log syntax or trustworthy event content.'}
