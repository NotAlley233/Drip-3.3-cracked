"""Versioned, atomic user profiles independent of executable extraction paths."""
import json
import os
from pathlib import Path
import re
import tempfile


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=path.name+'.', suffix='.tmp', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class ProfileStore:
    def __init__(self, folder, validate):
        self.folder = Path(folder)
        self.folder.mkdir(parents=True, exist_ok=True)
        self.validate = validate

    def path(self, name):
        if not isinstance(name, str) or not re.fullmatch(r'[\w\- ]{1,48}', name, re.UNICODE) or name.strip()!=name:
            raise ValueError('Profile name: 1-48 letters, numbers, spaces, underscores or hyphens')
        # Prefix also avoids reserved Windows device filenames.
        return self.folder / ('profile-'+name+'.json')

    def list(self):
        return sorted(p.stem[8:] for p in self.folder.glob('profile-*.json'))

    def save(self, name, values, enabled):
        if not isinstance(enabled, bool):
            raise ValueError('Boolean enabled required')
        atomic_json(self.path(name), {'format':'driplite-overrides-v1','values':self.validate(values),'enabled':enabled})

    def load(self, name):
        data = json.loads(self.path(name).read_text(encoding='utf-8'))
        if data.get('format')!='driplite-overrides-v1' or not isinstance(data.get('enabled',True),bool):
            raise ValueError('Invalid profile format')
        return self.validate(data['values']), data.get('enabled', True)

    def delete(self, name):
        self.path(name).unlink()
