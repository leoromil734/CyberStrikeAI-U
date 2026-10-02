import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

MODULE_PATH = Path(__file__).with_name("install_lite_wordlists.py")
SPEC = importlib.util.spec_from_file_location("install_lite_wordlists", MODULE_PATH)
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


class FakeResponse(io.BytesIO):
    def __init__(self, body, content_type="text/plain"):
        super().__init__(body)
        self.headers = {"Content-Type": content_type}


class LiteWordlistsTests(unittest.TestCase):
    def test_selection_preserves_order_and_hard_limit(self):
        data = b"\xef\xbb\xbf# comment\r\nfirst\r\n\r\nsecond\r\nfirst\r\nthird\r\n"
        self.assertEqual(installer.select_entries(data, 2, "password"), ["first", "second"])

    def test_filters_control_and_invalid_dns_or_path_lines(self):
        self.assertEqual(installer.select_entries(b"\x01bad\n*.wild\nwww\nmail\nbad name\n", 5, "dns"), ["www", "mail"])
        self.assertEqual(installer.select_entries(b".\n..\nhttps://third.party/\n/api/v1\nadmin\n", 10, "path"), ["/api/v1", "admin"])

    def test_rejects_empty_or_invalid_utf8(self):
        with self.assertRaises(ValueError):
            installer.select_entries(b"# comment\n\n", 10, "password")
        with self.assertRaises(UnicodeDecodeError):
            installer.select_entries(b"\xff\n", 10, "password")

    def test_downloads_are_pinned_and_size_bounded(self):
        with patch.object(installer.urllib.request, "urlopen", return_value=FakeResponse(b"alpha\n")) as mock:
            self.assertEqual(installer.download_source("LICENSE"), b"alpha\n")
        request = mock.call_args.args[0]
        self.assertIn(installer.COMMIT, request.full_url)
        self.assertEqual(mock.call_args.kwargs["timeout"], 25)
        with patch.object(installer, "MAX_SOURCE_BYTES", 3), patch.object(installer.urllib.request, "urlopen", return_value=FakeResponse(b"abcd")):
            with self.assertRaises(ValueError):
                installer.download_source("too-large.txt")

    def test_download_rejects_html_binary_and_bad_encoding(self):
        for data, content_type in [(b"<html>error</html>", "text/plain"), (b"error", "text/html"), (b"abc\0", "text/plain"), (b"\xff", "text/plain")]:
            with self.subTest(data=data):
                with patch.object(installer.urllib.request, "urlopen", return_value=FakeResponse(data, content_type)):
                    with self.assertRaises(ValueError):
                        installer.download_source("invalid.txt")

    def test_atomic_install_has_counts_hashes_license_and_usage_limits(self):
        def fake_download(path):
            if path == "LICENSE":
                return b"test license\n"
            return ("\n".join(f"item{i}" for i in range(1500)) + "\n").encode()

        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "lite"
            manifest = installer.install(output, downloader=fake_download)
            self.assertEqual(json.loads((output / "manifest.json").read_text("utf-8")), manifest)
            self.assertEqual(len(manifest["dictionaries"]), 5)
            self.assertLessEqual(manifest["total_entries"], 2270)
            for item in manifest["dictionaries"]:
                data = (output / item["file"]).read_bytes()
                self.assertEqual(len(data.splitlines()), item["entries"])
                self.assertEqual(item["entries"], item["limit"])
                self.assertEqual(hashlib.sha256(data).hexdigest(), item["sha256"])
                self.assertTrue(data.endswith(b"\n"))
            self.assertEqual((output / "LICENSE.SecLists").read_bytes(), b"test license\n")
            self.assertEqual(manifest["usage_limits"]["credential"]["attempts_per_identity"], 8)
            self.assertFalse(manifest["usage_limits"]["credential"]["full_username_password_product"])
            self.assertEqual(manifest["total_dictionary_bytes"], sum(item["bytes"] for item in manifest["dictionaries"]))

    def test_standard_profile_is_larger_than_the_legacy_dictionaries(self):
        content = ("\n".join(f"item{i}" for i in range(30000)) + "\n").encode()

        def fake_download(path):
            return b"test license\n" if path == "LICENSE" else content

        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "standard"
            manifest = installer.install(output, downloader=fake_download, profile="standard")
            self.assertEqual(manifest["profile"], "standard")
            self.assertEqual(manifest["total_entries"], 34500)
            counts = {item["file"]: item["entries"] for item in manifest["dictionaries"]}
            self.assertGreater(counts["passwords-top3000.txt"], 1722)
            self.assertGreater(counts["usernames-top500.txt"], 221)
            self.assertGreater(counts["web-paths-top25000.txt"], 20115)
            self.assertEqual(counts["subdomains-top5000.txt"], 5000)
            self.assertEqual(counts["api-paths-top1000.txt"], 1000)
            self.assertEqual(manifest["usage_limits"], installer.USAGE_LIMITS)
            for item in manifest["dictionaries"]:
                data = (output / item["file"]).read_bytes()
                self.assertEqual(hashlib.sha256(data).hexdigest(), item["sha256"])

    def test_unknown_profile_fails_before_creating_output(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "unknown"
            with self.assertRaises(ValueError):
                installer.install(output, profile="unbounded")
            self.assertFalse(output.exists())

    def test_failed_install_does_not_publish_partial_output(self):
        def fake_download(path):
            if path == installer.SOURCES[2][1]:
                raise OSError("simulated upstream failure")
            return b"test\n"

        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "lite"
            with self.assertRaises(OSError):
                installer.install(output, downloader=fake_download)
            self.assertFalse(output.exists())
            self.assertEqual(list(Path(temp).iterdir()), [])

    def test_existing_output_is_preserved_without_network_calls(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "lite"
            output.mkdir()
            sentinel = output / "existing.txt"
            sentinel.write_text("keep", encoding="utf-8")
            with patch.object(installer, "download_source") as downloader:
                with self.assertRaises(FileExistsError):
                    installer.install(output, downloader=downloader)
                downloader.assert_not_called()
            self.assertEqual(sentinel.read_text("utf-8"), "keep")


if __name__ == "__main__":
    unittest.main()
