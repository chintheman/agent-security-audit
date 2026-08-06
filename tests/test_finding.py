import unittest

from asa.finding import Category, Evidence, Finding, Severity, Source, sort_findings


def make_finding(check_id="secrets.example", location="a.env", severity=Severity.HIGH):
    return Finding(
        check_id=check_id,
        category=Category.SECRETS,
        severity=severity,
        title="Example finding",
        evidence=Evidence(file=location, variable_name="X"),
        fix="Do the thing",
        location=location,
    )


class TestFindingId(unittest.TestCase):
    def test_id_is_deterministic(self):
        f1 = make_finding()
        f2 = make_finding()
        self.assertEqual(f1.id, f2.id)

    def test_id_changes_with_location(self):
        f1 = make_finding(location="a.env")
        f2 = make_finding(location="b.env")
        self.assertNotEqual(f1.id, f2.id)

    def test_id_changes_with_check_id(self):
        f1 = make_finding(check_id="secrets.a")
        f2 = make_finding(check_id="secrets.b")
        self.assertNotEqual(f1.id, f2.id)

    def test_id_is_stable_across_reruns_same_input(self):
        # simulates re-running the scan on an unchanged target
        ids_first_run = {make_finding().id for _ in range(5)}
        ids_second_run = {make_finding().id for _ in range(5)}
        self.assertEqual(ids_first_run, ids_second_run)
        self.assertEqual(len(ids_first_run), 1)


class TestEvidenceToDict(unittest.TestCase):
    def test_never_leaks_a_value_field(self):
        ev = Evidence(file="x.env", variable_name="KEY", value_length=12, value_hash8="deadbeef")
        d = ev.to_dict()
        self.assertNotIn("value", d)
        self.assertEqual(d["value_hash8"], "deadbeef")


class TestFindingToDict(unittest.TestCase):
    def test_shape(self):
        f = make_finding()
        d = f.to_dict()
        expected_keys = {
            "id", "check_id", "category", "severity", "title", "evidence",
            "fix", "fix_time_estimate", "location", "confidence", "source",
            "auto_fixable", "references",
        }
        self.assertEqual(set(d.keys()), expected_keys)
        self.assertEqual(d["category"], "secrets")
        self.assertEqual(d["severity"], "high")
        self.assertEqual(d["source"], "heuristic")

    def test_ai_assist_source_serializes(self):
        f = make_finding()
        f.source = Source.AI_ASSIST
        f.confidence = "medium"
        d = f.to_dict()
        self.assertEqual(d["source"], "ai-assist")
        self.assertEqual(d["confidence"], "medium")


class TestSortFindings(unittest.TestCase):
    def test_severity_first(self):
        low = make_finding(location="low", severity=Severity.LOW)
        crit = make_finding(location="crit", severity=Severity.CRITICAL)
        med = make_finding(location="med", severity=Severity.MEDIUM)
        ordered = sort_findings([low, crit, med])
        self.assertEqual([f.severity for f in ordered], [Severity.CRITICAL, Severity.MEDIUM, Severity.LOW])

    def test_stable_ordering_for_equal_severity(self):
        a = make_finding(location="a", severity=Severity.HIGH)
        b = make_finding(location="b", severity=Severity.HIGH)
        ordered1 = sort_findings([b, a])
        ordered2 = sort_findings([b, a])
        self.assertEqual([f.id for f in ordered1], [f.id for f in ordered2])

    def test_empty_list(self):
        self.assertEqual(sort_findings([]), [])


if __name__ == "__main__":
    unittest.main()
