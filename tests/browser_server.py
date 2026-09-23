"""Disposable browser acceptance server; never opens the user's state."""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from server import create_server

with tempfile.TemporaryDirectory(prefix='reverseai-browser-') as directory:
    server = create_server(port=0, data_path=Path(directory) / 'state.json')
    server.quiet = True
    print(f'http://127.0.0.1:{server.server_port}', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
