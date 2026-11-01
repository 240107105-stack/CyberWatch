from datetime import datetime,timedelta
import sqlite3
import unittest

from db.database import add_event_record, change_alert_status, connect_database, initialize_database
from services.detection import BRUTE_FORCE, PORT_SCAN, SUCCESS_AFTER_FAILURE, run_detection


class DetectionTests(unittest.TestCase):
    def setUp(self):
        self.db=connect_database(":memory:")
        self.addCleanup(self.db.close)
        self.origin=datetime(2025,1,1,12)

    def event(self,seconds=0,kind="LOGIN_FAILED",ip="203.0.113.45",port=None):
        with self.db:
            add_event_record(self.db,ip,kind,"MEDIUM","test evidence",
                             (self.origin+timedelta(seconds=seconds)).isoformat(sep=" "),destination_port=port)

    def count(self,rule=None):
        if rule is None:
            return self.db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        return self.db.execute("SELECT COUNT(*) FROM alerts WHERE rule_name=?",(rule,)).fetchone()[0]

    def test_historical_attack_detected_at_inclusive_boundary_and_links_evidence(self):
        for second in (0,150,300,450,600):
            self.event(second,ip="2001:db8::12")
        result=run_detection(self.db)
        self.assertEqual((1,1),(result.suspicious_ips,result.new_alerts))
        self.assertEqual(5,self.db.execute("SELECT COUNT(*) FROM alert_events").fetchone()[0])
        self.assertEqual(1,self.db.execute("SELECT COUNT(*) FROM alert_history").fetchone()[0])

    def test_exact_legacy_alert_gets_evidence_without_duplicate_and_preserves_status(self):
        for second in range(5):
            self.event(second)
        fingerprint="BRUTE_FORCE:203.0.113.45:2025-01-01 12:00:00:2025-01-01 12:00:04:5"
        with self.db:
            self.db.execute("INSERT INTO alerts(fingerprint,created_at,source_ip,rule_name,severity,description,status) "
                            "VALUES (?,'2025-01-01 12:01:00','203.0.113.45',?,'HIGH','Legacy alert','RESOLVED')",
                            (fingerprint,BRUTE_FORCE))
        initialize_database(self.db)
        initialize_database(self.db)
        self.assertEqual(5,self.db.execute("SELECT COUNT(*) FROM alert_events").fetchone()[0])
        self.assertEqual(0,run_detection(self.db).new_alerts)
        self.assertEqual(1,self.count())
        self.assertEqual("RESOLVED",self.db.execute("SELECT status FROM alerts").fetchone()[0])
        for second in range(10,15):
            self.event(second)
        self.assertEqual(1,run_detection(self.db).new_alerts)
        self.assertEqual(2,self.count())

    def test_mismatched_legacy_fingerprint_is_not_given_guessed_evidence(self):
        for second in range(5):
            self.event(second)
        fingerprints=(
            "BRUTE_FORCE:203.0.113.45:2025-01-01 12:00:00:2025-01-01 12:00:04:6",
            "BRUTE_FORCE:203.0.113.45:2025-01-01 12:00:01:2025-01-01 12:00:04:5",
            "BRUTE_FORCE:203.0.113.46:2025-01-01 12:00:00:2025-01-01 12:00:04:5",
            "BRUTE_FORCE:203.0.113.45:2025-02-31 12:00:00:2025-02-31 12:00:04:5",
        )
        with self.db:
            for fingerprint in fingerprints:
                self.db.execute("INSERT INTO alerts(fingerprint,created_at,source_ip,rule_name,severity,description) "
                                "VALUES (?,'2025-01-01 12:01:00','203.0.113.45',?,'HIGH','Unverifiable')",
                                (fingerprint,BRUTE_FORCE))
        initialize_database(self.db)
        self.assertEqual(0,self.db.execute("SELECT COUNT(*) FROM alert_events").fetchone()[0])
        self.assertEqual(1,run_detection(self.db).new_alerts)

    def test_counts_outside_window_are_not_combined(self):
        for second in (0,151,302,453,604):
            self.event(second)
        self.assertEqual(0,run_detection(self.db).new_alerts)

    def test_repeated_scan_preserves_resolved_state_and_new_evidence_can_alert(self):
        for second in range(5):
            self.event(second)
        self.assertEqual(1,run_detection(self.db).new_alerts)
        identity=self.db.execute("SELECT id FROM alerts").fetchone()[0]
        change_alert_status(self.db,identity,"RESOLVED")
        repeated=run_detection(self.db)
        self.assertEqual((1,0),(repeated.suspicious_ips,repeated.new_alerts))
        self.event(6)
        self.assertEqual(0,run_detection(self.db).new_alerts)
        for second in (7,8,9,10):
            self.event(second)
        self.assertEqual(1,run_detection(self.db).new_alerts)
        self.assertEqual("RESOLVED",self.db.execute("SELECT status FROM alerts WHERE id=?",(identity,)).fetchone()[0])
        self.assertEqual(10,self.db.execute("SELECT COUNT(*) FROM alert_events").fetchone()[0])

    def test_changing_threshold_does_not_realert_on_consumed_events(self):
        for second in range(5):
            self.event(second)
        run_detection(self.db)
        self.assertEqual(0,run_detection(self.db,threshold=3).new_alerts)

    def test_success_after_failures_has_own_evidence_and_is_deduplicated(self):
        for second in range(5):
            self.event(second)
        self.event(5,kind="LOGIN_SUCCESS")
        self.assertEqual(2,run_detection(self.db).new_alerts)
        self.assertEqual(1,self.count(BRUTE_FORCE))
        self.assertEqual(1,self.count(SUCCESS_AFTER_FAILURE))
        self.assertEqual(0,run_detection(self.db).new_alerts)
        self.event(6,kind="LOGIN_SUCCESS")
        self.assertEqual(0,run_detection(self.db).new_alerts)

    def test_previous_success_resets_failure_sequence_for_success_rule(self):
        for second,kind in ((0,"LOGIN_FAILED"),(1,"LOGIN_FAILED"),(2,"LOGIN_SUCCESS"),
                            (3,"LOGIN_FAILED"),(4,"LOGIN_FAILED"),(5,"LOGIN_FAILED"),(6,"LOGIN_SUCCESS")):
            self.event(second,kind=kind)
        run_detection(self.db)
        self.assertEqual(0,self.count(SUCCESS_AFTER_FAILURE))

    def test_distinct_ports_needed_and_nonnetwork_events_not_counted(self):
        for second in range(20):
            self.event(second,kind="NETWORK_CONNECTION",port=22)
        self.event(21,kind="LOG_EVENT",port=23)
        self.assertEqual(0,run_detection(self.db,port_threshold=3).new_alerts)
        self.event(22,kind="NETWORK_CONNECTION",port=80)
        self.event(23,kind="NETWORK_CONNECTION",port=443)
        self.assertEqual(1,run_detection(self.db,port_threshold=3).new_alerts)
        self.assertEqual(1,self.count(PORT_SCAN))
        self.assertEqual(0,run_detection(self.db,port_threshold=3).new_alerts)

    def test_future_and_malformed_legacy_records_are_excluded(self):
        future=(datetime.now()+timedelta(days=2)).strftime("%Y-%m-%d %H:%M:%S")
        with self.db:
            for _ in range(5):
                self.db.execute("INSERT INTO events(timestamp,source_ip,event_type,severity,message) VALUES (?,?,?,?,?)",
                                (future,"203.0.113.45","LOGIN_FAILED","MEDIUM","future"))
                self.db.execute("INSERT INTO events(timestamp,source_ip,event_type,severity,message) VALUES (?,?,?,?,?)",
                                ("not a date","invalid","LOGIN_FAILED","MEDIUM","invalid"))
        self.assertEqual(0,run_detection(self.db).new_alerts)

    def test_creation_rolls_back_all_alert_evidence_on_error(self):
        for second in range(5):
            self.event(second)
        self.db.execute("CREATE TRIGGER fail_history BEFORE INSERT ON alert_history BEGIN SELECT RAISE(ABORT,'fixture'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            run_detection(self.db)
        self.assertEqual(0,self.count())
        self.assertEqual(0,self.db.execute("SELECT COUNT(*) FROM alert_events").fetchone()[0])

    def test_rule_parameters_validated(self):
        for arguments in ({"threshold":1},{"threshold":True},{"window_minutes":0},{"port_threshold":1001}):
            with self.subTest(arguments=arguments),self.assertRaises(ValueError):
                run_detection(self.db,**arguments)


if __name__ == "__main__":
    unittest.main()
