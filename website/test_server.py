"""Focused job contract checks; not executed while acceptance testing is on hold."""
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from website import jobs


class JobContractTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.runs = mock.patch.object(jobs, 'RUNS', Path(self.temp.name))
        self.runs.start()

    def tearDown(self):
        self.runs.stop()
        self.temp.cleanup()

    def test_upload_offsets_persist_and_original_names_are_confined(self):
        job = jobs.create(files=[{'name': '../../sample.log', 'size': 4, 'modified_ms': 1}])
        jobs.receive(job['id'], 0, 0, io.BytesIO(b'ab'), 2)
        saved = jobs.get(job['id'])
        self.assertEqual(saved['files'][0]['received_bytes'], 2)
        self.assertFalse(saved['files'][0]['received'])
        self.assertTrue(Path(saved['files'][0]['path']).is_relative_to(jobs.RUNS))
        with self.assertRaises(ValueError):
            jobs.receive(job['id'], 0, 0, io.BytesIO(b'cd'), 2)
        jobs.receive(job['id'], 0, 2, io.BytesIO(b'cd'), 2)
        saved = jobs.get(job['id'])
        self.assertTrue(saved['files'][0]['received'])
        self.assertEqual(Path(saved['files'][0]['path']).read_bytes(), b'abcd')

    def test_active_upload_blocks_replacement_until_cancelled(self):
        job = jobs.create(files=[{'name': 'sample.log', 'size': 4}])
        with self.assertRaises(ValueError):
            jobs.create(files=[{'name': 'other.log', 'size': 4}])
        self.assertEqual(jobs.cancel(job['id'])['status'], 'cancelled')
        replacement = jobs.create(files=[{'name': 'other.log', 'size': 4}])
        self.assertNotEqual(job['id'], replacement['id'])


if __name__ == '__main__':
    unittest.main()
