from datetime import datetime, timezone
import csv
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from db.database import initialize_database
from services.ingestion import event_key, import_log_file, ingest_lines, parse_line
from utils.network import normalize_ip, valid_ip
from utils.timeutils import log_timestamp, normalize_timestamp


NOW = datetime(2026, 11, 2, 12, 0, 0)


class ParsingTests(unittest.TestCase):
    def test_ssh_source_is_from_address_not_hostname(self):
        event = parse_line('2026-11-01T10:20:30 192.0.2.10 sshd: Failed password for root from 203.0.113.45 port 22', now=NOW)
        self.assertEqual('203.0.113.45', event.source_ip)
        self.assertEqual('LOGIN_FAILED', event.event_type)
        self.assertEqual('2026-11-01 10:20:30', event.timestamp)

    def test_invalid_from_is_not_replaced_by_host_ip(self):
        self.assertIsNone(parse_line('192.0.2.10 sshd: Failed password for root from 999.2.3.4 port 22', now=NOW))

    def test_ipv6_source_and_publickey_classification(self):
        event = parse_line('Nov  1 11:12:13 host sshd: Accepted publickey for analyst from 2001:0db8::0005 port 22', now=NOW)
        self.assertEqual('2001:db8::5', event.source_ip)
        self.assertEqual('LOGIN_SUCCESS', event.event_type)
        self.assertEqual('2026-11-01 11:12:13', event.timestamp)
        failed = parse_line('sshd: Failed publickey for root from [2001:db8::8]:2222', now=NOW)
        self.assertEqual('2001:db8::8', failed.source_ip)
        self.assertEqual('LOGIN_FAILED', failed.event_type)

    def test_offset_timestamp_converted_to_local_time(self):
        event = parse_line('2026-11-01T10:20:30+00:00 host Failed password for root from 203.0.113.1', now=NOW)
        expected = datetime(2026, 11, 1, 10, 20, 30, tzinfo=timezone.utc).astimezone().strftime('%Y-%m-%d %H:%M:%S')
        self.assertEqual(expected, event.timestamp)
        self.assertEqual(expected, normalize_timestamp('2026-11-01T10:20:30Z'))

    def test_bracketed_timestamp_and_rfc5424(self):
        for prefix in ('[2026-11-01 10:20:30]', '<34>1 2026-11-01T10:20:30'):
            with self.subTest(prefix=prefix):
                event = parse_line(prefix + ' host Failed password for root from 203.0.113.1', now=NOW)
                self.assertEqual('2026-11-01 10:20:30', event.timestamp)

    def test_year_boundary_and_missing_time(self):
        self.assertEqual('2025-12-31 23:59:59', log_timestamp('Dec 31 23:59:59 host test', now=datetime(2026, 1, 1, 0, 0, 0)))
        self.assertEqual('2026-11-02 12:00:00', parse_line('Failed password for root from 203.0.113.1', now=NOW).timestamp)

    def test_malformed_explicit_timestamps_are_skipped(self):
        for prefix in ('2026-13-01T10:20:30', '2026-11-01T25:20:30', '2026-11-01Tbad', 'Nov 32 11:20:30', 'Nov 01 badtime', '2026/11/01 10:20:30'):
            with self.subTest(prefix=prefix):
                self.assertIsNone(parse_line(prefix + ' Failed password for root from 203.0.113.1', now=NOW))
        record = {'timestamp':'2026-99-01', 'source_ip':'203.0.113.1', 'message':'Failed password'}
        self.assertIsNone(parse_line(json.dumps(record), now=NOW))

    def test_ufw_network_fields_and_port_validation(self):
        event = parse_line('2026-11-01T10:20:30 host kernel: [UFW BLOCK] SRC=2001:db8::5 DST=2001:db8::8 DPT=443 SPT=50000', now=NOW)
        self.assertEqual('NETWORK_CONNECTION', event.event_type)
        self.assertEqual('2001:db8::5', event.source_ip)
        self.assertEqual('2001:db8::8', event.destination_ip)
        self.assertEqual(443, event.destination_port)
        for suffix in ('DPT=99999', 'DPT=0', 'DPT=oops', 'DST=999.1.1.1 DPT=22'):
            with self.subTest(suffix=suffix):
                self.assertIsNone(parse_line('SRC=203.0.113.1 ' + suffix, now=NOW))

    def test_undated_ufw_prefix_uses_import_time(self):
        event=parse_line('[UFW BLOCK] SRC=198.51.100.23 DST=10.10.0.5 DPT=22',now=NOW)
        self.assertEqual('2026-11-02 12:00:00',event.timestamp)
        self.assertEqual('NETWORK_CONNECTION',event.event_type)
        self.assertEqual('198.51.100.23',event.source_ip)
        self.assertEqual('10.10.0.5',event.destination_ip)
        self.assertEqual(22,event.destination_port)

    def test_json_fields_roundtrip_and_invalid_types(self):
        record = dict(timestamp='2026-11-01 12:00:00', source_ip='2001:db8::6', destination_ip='10.0.0.5', destination_port='443', event_type='NETWORK_CONNECTION', severity='LOW', message='Connection to service')
        event = parse_line(json.dumps(record), now=NOW)
        self.assertEqual('2001:db8::6', event.source_ip)
        self.assertEqual(443, event.destination_port)
        self.assertEqual('NETWORK_CONNECTION', event.event_type)
        for field, value in (('timestamp',123),('source_ip',123),('destination_ip','invalid'),('destination_port',True),('severity','CRITICAL'),('event_type','INVALID EVENT'),('message',123)):
            with self.subTest(field=field):
                changed = {**record,field:value}
                self.assertIsNone(parse_line(json.dumps(changed), now=NOW))

    def test_blank_junk_and_overlong_message(self):
        for text in ('', '   ', 'garbage without IP', '{broken', '[1,2,3]', '999.0.0.1 test'):
            self.assertIsNone(parse_line(text, now=NOW))
        event = parse_line('Failed password from 203.0.113.1 ' + 'x' * 2000, now=NOW)
        self.assertEqual(1000,len(event.message))

    def test_network_validation(self):
        self.assertTrue(valid_ip('2001:db8::1'))
        self.assertEqual('2001:db8::1',normalize_ip('2001:0db8::1'))
        for value in (None, '', '999.0.0.1', '12345', 123):
            self.assertFalse(valid_ip(value))


class ImportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name)
        self.db = sqlite3.connect(':memory:')
        self.db.row_factory = sqlite3.Row
        self.addCleanup(self.db.close)
        initialize_database(self.db)

    def test_reimport_is_idempotent_and_identical_physical_lines_preserved(self):
        log = self.path/'auth.log'
        row = '2026-11-01T10:20:30 Failed password for root from 203.0.113.1\n'
        log.write_text(row * 5 + 'without address\n')
        first = import_log_file(self.db,log)
        second = import_log_file(self.db,log)
        self.assertEqual((5,1,0),(first.imported,first.skipped,first.duplicates))
        self.assertEqual((0,1,5),(second.imported,second.skipped,second.duplicates))
        self.assertEqual(5,self.db.execute('SELECT COUNT(*) FROM events').fetchone()[0])
        self.assertEqual(5,self.db.execute('SELECT COUNT(DISTINCT event_key) FROM events').fetchone()[0])
        self.assertEqual(str(log.resolve()),self.db.execute('SELECT source_file FROM events LIMIT 1').fetchone()[0])

    def test_missing_timestamp_reimport_does_not_create_fresh_copy(self):
        lines=[(1,'Failed password from 203.0.113.1')]
        self.assertEqual(1,ingest_lines(self.db,lines,'same-source',now=NOW).imported)
        self.assertEqual(1,ingest_lines(self.db,lines,'same-source',now=datetime(2026,11,3)).duplicates)

    def test_read_exception_rolls_back_batch(self):
        def failing_source():
            yield 1,'Failed password from 203.0.113.1'
            raise OSError('simulated source read error')
        with self.assertRaises(OSError):
            ingest_lines(self.db,failing_source(),'broken-source',now=NOW)
        self.assertEqual(0,self.db.execute('SELECT COUNT(*) FROM events').fetchone()[0])

    def test_jsonl_and_csv_roundtrip(self):
        record = dict(timestamp='2026-11-01 12:00:00', source_ip='2001:db8::9', event_type='LOGIN_FAILED', severity='MEDIUM', message='Failed publickey for user')
        filename=self.path/'event.jsonl'
        filename.write_text(json.dumps(record)+'\n')
        self.assertEqual(1,import_log_file(self.db,filename).imported)
        filename=self.path/'event.csv'
        with filename.open('w',newline='',encoding='utf-8-sig') as stream:
            writer=csv.DictWriter(stream,fieldnames=list(record))
            writer.writeheader()
            writer.writerow(record)
        self.assertEqual(1,import_log_file(self.db,filename).imported)
        self.assertEqual(1,import_log_file(self.db,filename).duplicates)
        rows=self.db.execute('SELECT timestamp,source_ip,event_type,severity,message FROM events').fetchall()
        self.assertEqual(tuple(rows[0]),tuple(rows[1]))

    def test_csv_bad_header_and_missing_source_do_not_write(self):
        filename=self.path/'broken.csv'
        filename.write_text('name,value\na,b\n')
        with self.assertRaises(ValueError):
            import_log_file(self.db,filename)
        with self.assertRaises(FileNotFoundError):
            import_log_file(self.db,self.path/'missing.log')
        self.assertEqual(0,self.db.execute('SELECT COUNT(*) FROM events').fetchone()[0])

    def test_fingerprint_uses_source_and_line_but_normalizes_line_ending(self):
        self.assertEqual(event_key('/file',1,'x\n'),event_key('/file',1,'x\r\n'))
        self.assertNotEqual(event_key('/file',1,'x'),event_key('/file',2,'x'))
        self.assertNotEqual(event_key('/file',1,'x'),event_key('/other',1,'x'))


if __name__ == '__main__':
    unittest.main()
