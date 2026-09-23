from pathlib import Path
import tempfile
import threading
import unittest

from server import Store


class StoreConcurrencyTests(unittest.TestCase):
    def test_reader_waits_for_write_transaction(self):
        with tempfile.TemporaryDirectory() as directory:
            store=Store(Path(directory)/'state.json')
            entered,done=threading.Event(),threading.Event()
            read=[]
            def reader():
                entered.set()
                read.append(store.load())
                done.set()
            with store.lock:
                worker=threading.Thread(target=reader)
                worker.start()
                self.assertTrue(entered.wait(1))
                self.assertFalse(done.wait(.05),'load must respect the ongoing transaction')
                data=store.load()
                data['marker']='committed'
                store.save(data)
            worker.join(timeout=2)
            self.assertTrue(done.is_set())
            self.assertEqual(read[0]['marker'],'committed')
