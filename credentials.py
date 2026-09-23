"""Credentials are encrypted with Windows DPAPI; never part of application state."""
import base64
import ctypes
import json
import os
from pathlib import Path
import threading


class Blob(ctypes.Structure):
    _fields_ = [('size', ctypes.c_ulong), ('data', ctypes.POINTER(ctypes.c_ubyte))]


def protect(data, decrypt=False):
    buffer = ctypes.create_string_buffer(data)
    source = Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
    output = Blob()
    if decrypt:
        ok = ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(output))
    else:
        ok = ctypes.windll.crypt32.CryptProtectData(ctypes.byref(source), 'ReverseAI credentials', None, None, None, 1, ctypes.byref(output))
    if not ok:
        raise ValueError('Windows 凭据加密/解密失败')
    try:
        return ctypes.string_at(output.data, output.size)
    finally:
        ctypes.windll.kernel32.LocalFree(output.data)


class Vault:
    def __init__(self, path):
        self.path = Path(path)
        self.lock = threading.RLock()
        self.memory = {}

    def _read(self):
        if os.name != 'nt':
            return dict(self.memory)
        if not self.path.exists():
            return {}
        return json.loads(protect(base64.b64decode(self.path.read_bytes()), decrypt=True))

    def set(self, key, value):
        with self.lock:
            values = self._read()
            if value:
                values[key] = value
            else:
                values.pop(key, None)
            if os.name == 'nt':
                data = protect(json.dumps(values).encode())
                temp = self.path.with_suffix('.tmp')
                temp.write_bytes(base64.b64encode(data))
                temp.replace(self.path)
            else:
                self.memory = values

    def get(self, key, env=''):
        with self.lock:
            return self._read().get(key) or (os.environ.get(env, '') if env else '')

    def status(self, key, env=''):
        return {'configured': bool(self.get(key, env)), 'storage': 'windows-dpapi' if os.name == 'nt' else 'session-memory'}
