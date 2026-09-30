"""Тесты app/github_releases.py: python3 -m unittest tests/test_github_releases.py
Сеть не используется — GitHub API и скачивание замоканы. Проверяем только критичное:
отбор правильного ассета (Windows x64, а не x86/client/arm), фильтр по мажорной версии 3
и то, что скачанный файл реально сверяется с контрольной суммой от GitHub."""
import hashlib
import os
import sys
import unittest
from unittest.mock import patch

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "app"))
import github_releases as gr  # noqa: E402


def _asset(name, url="https://example.invalid/" + "x", digest=None, size=1000):
    a = {"name": name, "browser_download_url": url + name, "size": size}
    if digest:
        a["digest"] = digest
    return a


def _release(tag, assets, draft=False):
    return {"tag_name": tag, "draft": draft, "assets": assets}


class AssetSelectionTest(unittest.TestCase):
    """Среди нескольких ассетов релиза должен выбираться именно aspia-host-*-x86_64.msi."""

    def test_picks_host_x64_ignores_others(self):
        page1 = [_release("v3.0.20", [
            _asset("aspia-client-3.0.20-x86_64.msi"),
            _asset("aspia-host-3.0.20-x86.msi"),
            _asset("aspia-host-3.0.20-arm64.apk"),
            _asset("aspia-host-3.0.20-x86_64.deb"),
            _asset("aspia-host-3.0.20-x86_64.msi", digest="sha256:" + "ab" * 32),
        ])]
        with patch.object(gr, "_http_get_json", side_effect=[page1, []]):
            data = gr._fetch_all()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["version"], "3.0.20")
        self.assertEqual(data[0]["asset_name"], "aspia-host-3.0.20-x86_64.msi")
        self.assertEqual(data[0]["sha256"], "ab" * 32)

    def test_release_without_matching_asset_is_skipped(self):
        page1 = [_release("v3.1.0", [_asset("aspia-host-3.1.0-x86.msi")])]
        with patch.object(gr, "_http_get_json", side_effect=[page1, []]):
            data = gr._fetch_all()
        self.assertEqual(data, [])

    def test_draft_and_non_v3_releases_excluded(self):
        page1 = [
            _release("v4.0.0", [_asset("aspia-host-4.0.0-x86_64.msi")]),
            _release("v3.2.0", [_asset("aspia-host-3.2.0-x86_64.msi")], draft=True),
            _release("v3.1.0", [_asset("aspia-host-3.1.0-x86_64.msi")]),
        ]
        with patch.object(gr, "_http_get_json", side_effect=[page1, []]):
            data = gr._fetch_all()
        self.assertEqual([r["version"] for r in data], ["3.1.0"])

    def test_results_sorted_newest_first(self):
        page1 = [
            _release("v3.0.5", [_asset("aspia-host-3.0.5-x86_64.msi")]),
            _release("v3.10.0", [_asset("aspia-host-3.10.0-x86_64.msi")]),
            _release("v3.2.0", [_asset("aspia-host-3.2.0-x86_64.msi")]),
        ]
        with patch.object(gr, "_http_get_json", side_effect=[page1, []]):
            data = gr._fetch_all()
        self.assertEqual([r["version"] for r in data], ["3.10.0", "3.2.0", "3.0.5"])


class DownloadIntegrityTest(unittest.TestCase):
    """Главный риск: скачанный с GitHub файл должен реально сверяться с присланной суммой,
    а не просто сохраняться на веру."""

    def _fake_urlopen(self, content):
        class _Resp:
            def __enter__(self_): return self_
            def __exit__(self_, *a): return False
            def read(self_, n=-1):
                if not hasattr(self_, "_sent"):
                    self_._sent = True
                    return content
                return b""
        return lambda *a, **k: _Resp()

    def test_matching_checksum_succeeds(self, tmp_path=None):
        import tempfile
        content = b"fake msi bytes"
        release = {"download_url": "https://example.invalid/f.msi",
                   "sha256": hashlib.sha256(content).hexdigest()}
        with tempfile.TemporaryDirectory() as d:
            dest = os.path.join(d, "out.msi")
            with patch.object(gr.urllib.request, "urlopen", self._fake_urlopen(content)):
                gr.download_release(release, dest, max_bytes=10_000_000)
            self.assertEqual(open(dest, "rb").read(), content)

    def test_mismatched_checksum_raises(self):
        import tempfile
        content = b"fake msi bytes"
        release = {"download_url": "https://example.invalid/f.msi",
                   "sha256": "0" * 64}
        with tempfile.TemporaryDirectory() as d:
            dest = os.path.join(d, "out.msi")
            with patch.object(gr.urllib.request, "urlopen", self._fake_urlopen(content)):
                with self.assertRaises(gr.ReleasesError):
                    gr.download_release(release, dest, max_bytes=10_000_000)

    def test_oversized_download_rejected(self):
        import tempfile
        content = b"x" * 1000
        release = {"download_url": "https://example.invalid/f.msi", "sha256": None}
        with tempfile.TemporaryDirectory() as d:
            dest = os.path.join(d, "out.msi")
            with patch.object(gr.urllib.request, "urlopen", self._fake_urlopen(content)):
                with self.assertRaises(gr.ReleasesError):
                    gr.download_release(release, dest, max_bytes=10)


if __name__ == "__main__":
    unittest.main()
