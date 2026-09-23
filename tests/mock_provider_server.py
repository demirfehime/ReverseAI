"""Local deterministic provider used only by browser acceptance tests."""
from http.server import ThreadingHTTPServer
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_runtime import FakeService


class AgentFixture(FakeService):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        prompt = json.loads(body['messages'][-1]['content'])
        if 'child_results' not in prompt:
            answer = 'Fixture child finding with evidence limitations.'
        elif not prompt['child_results']:
            answer = json.dumps({'action': 'spawn_agents', 'tasks': ['Check evidence', 'Check missing inputs']})
        else:
            answer = json.dumps({'action': 'finish', 'answer': 'Fixture summary from two child results.'})
        self.reply({'choices': [{'message': {'content': answer}}]})

server = ThreadingHTTPServer(('127.0.0.1', 0), AgentFixture if '--agents' in sys.argv else FakeService)
print(f'http://127.0.0.1:{server.server_port}/v1', flush=True)
try:
    server.serve_forever()
except KeyboardInterrupt:
    pass
finally:
    server.server_close()
