import datetime
import importlib.util
import pathlib
import unittest

spec = importlib.util.spec_from_file_location("rc", pathlib.Path(__file__).parent / "release-channel.py")
rc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rc)

IMAGE = "ghcr.io/seawise-io/seawise-client"
DIGEST = "sha256:" + "a" * 64
NOW = datetime.datetime(2027, 1, 1, tzinfo=datetime.timezone.utc)


def manifest(**kw):
    m = {"channel": "stable", "image": IMAGE, "version": "2.1.0", "digest": DIGEST,
         "expires": "2027-01-15T00:00:00Z"}
    m.update(kw)
    return m


class ClassifyTest(unittest.TestCase):
    def test_v1(self):
        for tag in ["v1.0.12", "v1.0.13", "v1.1.0", "v1.0.13-rc.1"]:
            self.assertEqual(rc.classify(tag)["line"], "v1", tag)
            self.assertEqual(rc.classify(tag)["tags"], "", tag)

    def test_v2(self):
        cases = {
            "v2.0.0": ("2.0.0", "false"),
            "v2.0.0-beta.1": ("2.0.0-beta.1", "true"),
            "v2.3.10-rc.2": ("2.3.10-rc.2", "true"),
        }
        for tag, (version, pre) in cases.items():
            got = rc.classify(tag)
            self.assertEqual(got["line"], "v2", tag)
            self.assertEqual(got["version"], version, tag)
            self.assertEqual(got["prerelease"], pre, tag)
            self.assertEqual(got["tags"].split(), [version, "2", "beta"], tag)

    def test_v2_never_latest_or_v1(self):
        for tag in ["v2.0.0", "v2.0.0-beta.1", "v2.9.9"]:
            for t in rc.classify(tag)["tags"].split():
                self.assertNotEqual(t, "latest")
                self.assertFalse(t == "1" or t.startswith("1."), t)

    def test_rejected(self):
        for tag in ["v2", "v2.0", "v2.0.0.1", "v2.01.0", "v2.0.0-", "v2.0.0+build",
                    "v2.0.0-beta..1", "v20.0.0", "v3.0.0", "v0.9.0", "vlatest",
                    "v2.0.0\n", "v2.0.0-beta_1", "v2.٣.0"]:
            with self.assertRaises(rc.Error, msg=tag):
                rc.classify(tag)


class ManifestTest(unittest.TestCase):
    def test_ok(self):
        self.assertEqual(rc.check_manifest(manifest(), "2.1.0", IMAGE, NOW), DIGEST)

    def test_rejected(self):
        bad = [
            (manifest(), "2.1.0-beta.1"),
            (manifest(), "2.2.0"),
            (manifest(channel="beta"), "2.1.0"),
            (manifest(image="ghcr.io/other/image"), "2.1.0"),
            (manifest(digest="sha256:abc"), "2.1.0"),
            (manifest(digest=None), "2.1.0"),
            (manifest(expires="2026-12-31T23:59:59Z"), "2.1.0"),
            (manifest(expires="2027-01-15T00:00:00"), "2.1.0"),
            (manifest(expires="soon"), "2.1.0"),
            (manifest(extra=1), "2.1.0"),
            ({k: v for k, v in manifest().items() if k != "expires"}, "2.1.0"),
            ([], "2.1.0"),
        ]
        for data, version in bad:
            with self.assertRaises(rc.Error, msg=(data, version)):
                rc.check_manifest(data, version, IMAGE, NOW)


if __name__ == "__main__":
    unittest.main()
