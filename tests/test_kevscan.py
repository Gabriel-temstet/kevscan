import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import kevscan as k  # noqa: E402

CATALOG = (ROOT / "examples" / "catalogue-exemple.csv").read_text(encoding="utf-8")


class TestKevscan(unittest.TestCase):
    def test_parse_banner(self):
        self.assertEqual(k.parse_banner("SSH-2.0-OpenSSH_8.2p1 Ubuntu"), [("OpenSSH", "8.2p1")])
        self.assertEqual(k.parse_banner("HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)"),
                         [("Apache", "2.4.49")])

    def test_catalog_columns_are_normalised(self):
        cat = k.parse_catalog(CATALOG)
        self.assertEqual(len(cat), 2)
        self.assertEqual(cat[0]["cve"], "CVE-2021-41773")
        self.assertEqual(cat[0]["ransom"], "Known")

    def test_invalid_catalog(self):
        with self.assertRaises(SystemExit):
            k.parse_catalog("a,b\n1,2\n")

    def test_correlate(self):
        cat = k.parse_catalog(CATALOG)
        items = [k.Item("Apache HTTP Server", "2.4.49"), k.Item("Notepad", "1.0")]
        res = k.correlate(items, cat)
        self.assertEqual([f.entry["cve"] for f in res], ["CVE-2021-41773"])

    def test_check_version(self):
        m = [{"criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
              "versionStartIncluding": "2.4.49", "versionEndIncluding": "2.4.50"}]
        tk = k.Item("Apache HTTP Server").tokens
        self.assertTrue(k.check_version(tk, "2.4.49", m))
        self.assertFalse(k.check_version(tk, "2.4.51", m))
        self.assertIsNone(k.check_version(tk, "", m))
        self.assertIsNone(k.check_version(k.Item("Notepad").tokens, "1.0", m))

    def test_version_compare(self):
        self.assertEqual(k.vcmp(k.vkey("2.4"), k.vkey("2.4.0")), 0)
        self.assertEqual(k.vcmp(k.vkey("2.10"), k.vkey("2.9")), 1)

    def test_parse_cvss_prefers_v31_primary(self):
        obj = {"metrics": {"cvssMetricV31": [{"type": "Primary",
                                              "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]}}
        self.assertEqual(k.parse_cvss(obj), (9.8, "CRITICAL"))
        self.assertEqual(k.parse_cvss({}), (None, ""))

    def test_inventory_csv(self):
        items = k.inv_csv_text("host,name,version\nSRV1,OpenSSH,8.2p1\n")
        self.assertEqual((items[0].name, items[0].version, items[0].source), ("OpenSSH", "8.2p1", "SRV1"))

    def test_expand_targets(self):
        self.assertEqual(k.expand_targets(["10.0.0.0/30"], allow_files=False), ["10.0.0.1", "10.0.0.2"])
        self.assertEqual(k.expand_targets(["10.0.0.5"], allow_files=False), ["10.0.0.5"])

    def test_report_html_escapes_and_contains_data(self):
        cat = k.parse_catalog(CATALOG)
        fs = k.correlate([k.Item("Apache HTTP Server", "<b>2.4.49</b>", "srv")], cat)
        meta = k.make_meta("ACME <x>", "Kapelgy", "", "", "test", 1, "KEV")
        out = k.build_html(fs, meta)
        self.assertIn("CVE-2021-41773", out)
        self.assertNotIn("<b>2.4.49</b>", out)
        self.assertIn("ACME &lt;x&gt;", out)

    def test_sort_puts_ransomware_first(self):
        cat = k.parse_catalog(CATALOG)
        fs = k.correlate([k.Item("Google Chromium WebP", "1"), k.Item("Apache HTTP Server", "1")], cat)
        self.assertEqual(k.sort_findings(fs)[0].entry["cve"], "CVE-2021-41773")


if __name__ == "__main__":
    unittest.main()
