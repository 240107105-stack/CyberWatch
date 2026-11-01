from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from services.live import LogTailer


class TailerTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path=Path(self.temporary.name)/'live.log'
        self.path.write_text('old record\n')

    def tailer(self,**kwargs):
        tail=LogTailer(self.path,**kwargs)
        self.addCleanup(tail.close)
        return tail

    def append(self,text):
        with self.path.open('a') as stream:
            stream.write(text)

    def test_only_complete_new_lines_are_returned(self):
        tail=self.tailer()
        self.assertEqual([],tail.read_new())
        self.append('new partial')
        self.assertEqual([],tail.read_new())
        self.append(' line\nsecond\n')
        self.assertEqual([(1,'new partial line\n'),(2,'second\n')],tail.read_new())
        self.assertEqual([],tail.read_new())

    def test_start_from_beginning_and_bounded_lines(self):
        self.path.write_text('a\nb\nc\nd\n')
        tail=self.tailer(from_start=True,max_lines=2)
        self.assertEqual([(1,'a\n'),(2,'b\n')],tail.read_new())
        self.assertEqual([(3,'c\n'),(4,'d\n')],tail.read_new())
        self.assertEqual([],tail.read_new())

    def test_byte_limit_keeps_partial_utf8_until_complete(self):
        tail=self.tailer(max_bytes=3)
        self.append('тест\n')
        results=[]
        for _ in range(4):
            results.extend(tail.read_new())
        self.assertEqual([(1,'тест\n')],results)

    def test_rotation_reopens_replacement_file(self):
        tail=self.tailer()
        old_source=tail.source_id
        self.path.rename(self.path.with_suffix('.1'))
        self.path.write_text('rotated record\n')
        self.assertEqual([(1,'rotated record\n')],tail.read_new())
        self.assertNotEqual(old_source,tail.source_id)

    def test_rename_gap_waits_for_replacement(self):
        tail=self.tailer()
        self.path.rename(self.path.with_suffix('.1'))
        self.assertEqual([],tail.read_new())
        self.path.write_text('new file\n')
        self.assertEqual([(1,'new file\n')],tail.read_new())

    def test_truncation_discards_previous_partial_buffer(self):
        tail=self.tailer()
        self.append('old partial')
        self.assertEqual([],tail.read_new())
        old_source=tail.source_id
        self.path.write_text('fresh\n')
        self.assertEqual([(1,'fresh\n')],tail.read_new())
        self.assertNotEqual(old_source,tail.source_id)

    def test_copytruncate_regrowing_past_old_offset_is_detected(self):
        tail=self.tailer()
        self.path.write_text('entirely new content longer than original file\n')
        self.assertEqual([(1,'entirely new content longer than original file\n')],tail.read_new())

    def test_existing_unterminated_fragment_is_not_imported_as_new_line(self):
        self.path.write_text('already existing partial')
        tail=self.tailer()
        self.append(' suffix\nreally new\n')
        self.assertEqual([(2,'really new\n')],tail.read_new())

    def test_oversized_record_is_bounded_and_next_line_recovers(self):
        self.path.write_text('')
        tail=self.tailer(from_start=True,max_bytes=8,max_line_bytes=10)
        self.append('x'*30+'\nok\n')
        results=[]
        for _ in range(10):
            results.extend(tail.read_new())
            self.assertLessEqual(len(tail._buffer),18)
        self.assertEqual([(1,''),(2,'ok\n')],results)

    def test_rotation_drains_buffered_and_unread_old_lines_before_switching_source(self):
        for max_bytes in (262144, 5):
            with self.subTest(max_bytes=max_bytes):
                self.path.write_text('')
                tail=self.tailer(max_lines=1,max_bytes=max_bytes)
                self.append('old1\nold2\nold3\n')
                old_source=tail.source_id
                self.assertEqual([(1,'old1\n')],tail.read_new())
                self.path.rename(self.path.with_suffix('.rotated'))
                self.path.write_text('new1\n')
                self.assertEqual([(2,'old2\n')],tail.read_new())
                self.assertEqual(old_source,tail.source_id)
                self.assertEqual([(3,'old3\n')],tail.read_new())
                self.assertEqual(old_source,tail.source_id)
                self.assertEqual([(1,'new1\n')],tail.read_new())
                self.assertNotEqual(old_source,tail.source_id)
                tail.close()

    def test_truncation_drains_complete_buffer_before_rewinding(self):
        self.path.write_text('')
        tail=self.tailer(max_lines=1)
        self.append('old1\nold2\nold3\n')
        self.assertEqual([(1,'old1\n')],tail.read_new())
        old_source=tail.source_id
        self.path.write_text('new first record longer than old file\nnew second\n')
        self.assertEqual([(2,'old2\n')],tail.read_new())
        self.assertEqual(old_source,tail.source_id)
        self.assertEqual([(3,'old3\n')],tail.read_new())
        self.assertEqual(old_source,tail.source_id)
        self.assertEqual([(1,'new first record longer than old file\n')],tail.read_new())
        self.assertNotEqual(old_source,tail.source_id)
        self.assertEqual([(2,'new second\n')],tail.read_new())

    def test_read_at_fallback_keeps_cursor_and_detects_rewrite(self):
        with patch('services.live.os.pread',None,create=True):
            tail=self.tailer(max_lines=1)
            self.append('one\ntwo\n')
            self.assertEqual([(1,'one\n')],tail.read_new())
            self.assertEqual([(2,'two\n')],tail.read_new())
            self.path.write_text('rewritten file longer than prior contents\n')
            self.assertEqual([(1,'rewritten file longer than prior contents\n')],tail.read_new())

    def test_missing_initial_file_and_closed_reader(self):
        with self.assertRaises(FileNotFoundError):
            LogTailer(self.path.with_suffix('.missing'))
        tail=self.tailer()
        tail.close()
        tail.close()
        with self.assertRaises(ValueError):
            tail.read_new()
        for kwargs in ({'max_lines':0},{'max_bytes':0},{'max_line_bytes':0}):
            with self.assertRaises(ValueError):
                LogTailer(self.path,**kwargs)


if __name__=='__main__':
    unittest.main()
