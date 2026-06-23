"""Offline tests for the data-feed catalog and edge/air-gap helpers.

These NEVER hit the network: they exercise catalog parsing, listing/filtering,
the offline cache guard, and the air-gap snapshot round-trip against a temp
cache dir. The live fetch paths (update/get-online/harvest) are intentionally
not exercised here — CI runs offline.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from licenselens import datafeeds  # noqa: E402


class TestCatalog(unittest.TestCase):
    def test_catalog_loads(self):
        cat = datafeeds.load_catalog()
        self.assertIn("feeds", cat)
        self.assertGreater(len(cat["feeds"]), 10)

    def test_every_feed_has_required_fields(self):
        for f in datafeeds.load_catalog()["feeds"]:
            for key in ("id", "name", "url", "domain"):
                self.assertIn(key, f, f"feed missing {key}: {f.get('id')}")

    def test_feeds_are_http_urls(self):
        for f in datafeeds.load_catalog()["feeds"]:
            self.assertTrue(f["url"].startswith(("https://", "http://")), f["id"])

    def test_feeds_mostly_https(self):
        feeds = datafeeds.load_catalog()["feeds"]
        https = sum(1 for f in feeds if f["url"].startswith("https://"))
        # The catalog is overwhelmingly TLS; a couple of legacy feeds may not be.
        self.assertGreater(https, 0.8 * len(feeds))

    def test_list_filter_by_domain(self):
        vuln = datafeeds.list_feeds(domain="vuln")
        self.assertTrue(vuln)
        self.assertTrue(all(f["domain"] == "vuln" for f in vuln))

    def test_known_vuln_feeds_present(self):
        ids = {f["id"] for f in datafeeds.list_feeds(domain="vuln")}
        for expected in ("cisa-kev", "osv", "nvd-cve"):
            self.assertIn(expected, ids)

    def test_unique_feed_ids(self):
        ids = [f["id"] for f in datafeeds.load_catalog()["feeds"]]
        self.assertEqual(len(ids), len(set(ids)))


class TestOfflineGuard(unittest.TestCase):
    def test_offline_missing_raises(self):
        with tempfile.TemporaryDirectory() as d:
            os.environ["COGNIS_FEEDS_CACHE"] = d
            try:
                with self.assertRaises(FileNotFoundError):
                    datafeeds.get("cisa-kev", offline=True)
            finally:
                os.environ.pop("COGNIS_FEEDS_CACHE", None)

    def test_cached_age_none_when_absent(self):
        with tempfile.TemporaryDirectory() as d:
            os.environ["COGNIS_FEEDS_CACHE"] = d
            try:
                self.assertIsNone(datafeeds.cached_age_hours("nvd-cve"))
            finally:
                os.environ.pop("COGNIS_FEEDS_CACHE", None)


class TestSnapshotRoundTrip(unittest.TestCase):
    def test_export_import_flat(self):
        with tempfile.TemporaryDirectory() as src, tempfile.TemporaryDirectory() as dst:
            # Seed a fake cached feed in src.
            os.environ["COGNIS_FEEDS_CACHE"] = src
            try:
                cd = datafeeds.cache_dir()
                (cd / "fakefeed.data").write_bytes(b'{"ok": true}')
                (cd / "fakefeed.meta.json").write_text('{"feed":"fakefeed","fetched_at":0}')
                archive = os.path.join(dst, "snap.tar.gz")
                n = datafeeds.snapshot_export(archive)
                self.assertEqual(n, 1)
                self.assertTrue(os.path.exists(archive))
            finally:
                os.environ.pop("COGNIS_FEEDS_CACHE", None)

            # Import into a different cache dir.
            os.environ["COGNIS_FEEDS_CACHE"] = dst
            try:
                imported = datafeeds.snapshot_import(archive)
                self.assertEqual(imported, 1)
                self.assertTrue((datafeeds.cache_dir() / "fakefeed.data").exists())
            finally:
                os.environ.pop("COGNIS_FEEDS_CACHE", None)


if __name__ == "__main__":
    unittest.main()
