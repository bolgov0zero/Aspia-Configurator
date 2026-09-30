"""Тесты ядра: python3 -m unittest tests/test_msipatch.py  (нужны wixl, msitools, gcab)."""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "app"))
import msipatch  # noqa: E402
sys.path.insert(0, HERE)
import oledir  # noqa: E402
import msicheck  # noqa: E402


def _tables(msi, t):
    return msipatch._export_table(msi, t)


def _make_importable(msi, source, filename="app-settings.json", dir_prop="SourceDir"):
    """Добавляет в тестовый MSI штатный для пакетов Aspia Host custom action ImportSettings,
    запускающий файл с ключом `source` из таблицы File с командой --import="[dir_prop]filename" --silent."""
    target = '--import="[%s]%s" --silent' % (dir_prop, filename)
    subprocess.run(["msibuild", msi,
                    "-q", "INSERT INTO `CustomAction` (`Action`,`Type`,`Source`,`Target`) VALUES "
                          "('ImportSettings',3218,'%s','%s')" % (source, target),
                    "-q", "INSERT INTO `InstallExecuteSequence` (`Action`,`Condition`,`Sequence`) VALUES "
                          "('ImportSettings','',4001)"],
                   check=True, capture_output=True)


@unittest.skipUnless(shutil.which("wixl") and shutil.which("msibuild") and shutil.which("gcab"), "нет wixl/msitools/gcab")
class ImportFileTest(unittest.TestCase):
    """Проверяет add_import_file() на синтетических пакетах, которым вручную добавлен ImportSettings
    того же вида, что у настоящих пакетов Aspia Host (см. RealPackageTest для проверки на реальном)."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        shutil.copy(os.path.join(HERE, "hello.txt"), cls.tmp)
        shutil.copy(os.path.join(HERE, "test.wxs"), cls.tmp)
        shutil.copy(os.path.join(HERE, "multi.wxs"), cls.tmp)

        cls.plain = os.path.join(cls.tmp, "plain.msi")             # без ImportSettings
        subprocess.run(["wixl", "-o", cls.plain, os.path.join(cls.tmp, "test.wxs")],
                       cwd=cls.tmp, check=True, capture_output=True)

        cls.base = os.path.join(cls.tmp, "base.msi")               # с ImportSettings, как у Aspia Host
        shutil.copy(cls.plain, cls.base)
        _make_importable(cls.base, source="hello")

        cls.multi = os.path.join(cls.tmp, "multi.msi")             # два Feature: ImportSettings ссылается на файл из FeatB
        subprocess.run(["wixl", "-o", cls.multi, os.path.join(cls.tmp, "multi.wxs")],
                       cwd=cls.tmp, check=True, capture_output=True)
        _make_importable(cls.multi, source="zfile")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _add(self, src, name="app-settings.json", data=b'{"x":1}\n', **kw):
        wd = tempfile.mkdtemp(dir=self.tmp)
        payload = os.path.join(wd, "payload")
        with open(payload, "wb") as f:
            f.write(data)
        dst = os.path.join(wd, "out.msi")
        res = msipatch.add_import_file(src, dst, payload, name, wd, **kw)
        return dst, res

    def test_requires_import_action(self):
        with self.assertRaises(msipatch.MsiError):
            self._add(self.plain)

    def test_describe_importable_flag(self):
        self.assertFalse(msipatch.describe(self.plain)["importable"])
        self.assertTrue(msipatch.describe(self.base)["importable"])

    def test_rejects_unexpected_target_shape(self):
        odd = os.path.join(self.tmp, "odd.msi")
        shutil.copy(self.plain, odd)
        subprocess.run(["msibuild", odd, "-q",
                       "INSERT INTO `CustomAction` (`Action`,`Type`,`Source`,`Target`) VALUES "
                       "('ImportSettings',3218,'hello','--do-something-else')"],
                       check=True, capture_output=True)
        with self.assertRaises(msipatch.MsiError):
            self._add(odd)

    def test_rows_and_command(self):
        dst, res = self._add(self.base)
        self.assertEqual(res.temp_path, "%TEMP%\\app-settings.json")
        self.assertIn('[TempFolder]app-settings.json', res.command)
        self.assertIn("--silent", res.command)                      # остальная часть команды сохранена
        ca = {r["Action"]: r for r in _tables(dst, "CustomAction")}
        self.assertEqual(ca["ImportSettings"]["Target"], res.command)
        self.assertEqual(ca["ImportSettings"]["Type"], "3218")       # Type не менялся
        self.assertEqual(ca["ImportSettings"]["Source"], "hello")    # Source не менялся
        files = {msipatch._long_name(r["FileName"]): r for r in _tables(dst, "File")}
        self.assertIn("app-settings.json", files)
        dirs = {r["Directory"]: r for r in _tables(dst, "Directory")}
        self.assertEqual(dirs["TempFolder"]["Directory_Parent"], "TARGETDIR")

    def test_feature_scoped_to_exe_feature_only(self):
        dst, _ = self._add(self.multi, name="cfg.json")
        comp = next(r["Component_"] for r in _tables(dst, "File") if msipatch._long_name(r["FileName"]) == "cfg.json")
        feats = {r["Feature_"] for r in _tables(dst, "FeatureComponents") if r["Component_"] == comp}
        self.assertEqual(feats, {"FeatB"})                          # не FeatA — там нет запускаемого exe

    def test_removefile_added_by_default(self):
        dst, res = self._add(self.base)
        self.assertIsNotNone(res.cleanup)
        rf = _tables(dst, "RemoveFile")
        self.assertEqual(len(rf), 1)
        self.assertEqual(rf[0]["DirProperty"], "TempFolder")
        self.assertEqual(rf[0]["InstallMode"], "3")

    def test_removefile_skipped_when_disabled(self):
        dst, res = self._add(self.base, delete_after=False)
        self.assertIsNone(res.cleanup)
        self.assertEqual(_tables(dst, "RemoveFile"), [])

    def test_tables_stay_sorted(self):
        dst, _ = self._add(self.base)
        if not shutil.which("gsf"):
            self.skipTest("нет gsf")
        self.assertEqual(msicheck.unsorted_tables(dst, msipatch._tool("msiinfo"), msipatch._tool_env()), [])

    def test_package_code_kept_by_default(self):
        dst, res = self._add(self.base)
        old = {r["PropertyId"]: r["Value"] for r in _tables(self.base, "_SummaryInformation")}["9"]
        new = {r["PropertyId"]: r["Value"] for r in _tables(dst, "_SummaryInformation")}["9"]
        self.assertEqual(old, new)
        self.assertIsNone(res.package_code)

    def test_package_code_changed_on_request(self):
        dst, res = self._add(self.base, new_package_code=True)
        old = {r["PropertyId"]: r["Value"] for r in _tables(self.base, "_SummaryInformation")}["9"]
        new = {r["PropertyId"]: r["Value"] for r in _tables(dst, "_SummaryInformation")}["9"]
        self.assertNotEqual(old, new)
        self.assertEqual(new, res.package_code)

    def test_twice_and_duplicate(self):
        first, _ = self._add(self.base, name="a.json")
        second, _ = self._add(first, name="b.json")           # TempFolder уже есть — переиспользуется
        names = [msipatch._long_name(r["FileName"]) for r in _tables(second, "File")]
        self.assertIn("a.json", names)
        self.assertIn("b.json", names)
        with self.assertRaises(msipatch.MsiError):
            self._add(second, name="A.JSON")                    # дубликат без учёта регистра

    def test_long_and_short_names(self):
        dst, _ = self._add(self.base, name="my settings file.json")
        self.assertIn("MYSETT~1.JSO|my settings file.json", [r["FileName"] for r in _tables(dst, "File")])

    def test_bad_names(self):
        for bad in ("настройки.json", "a/b.json", "con.txt", "x'y.json", "", "a:b"):
            with self.assertRaises(msipatch.MsiError, msg=bad):
                self._add(self.base, name=bad)

    def test_missing_msifilehash_table(self):
        src = os.path.join(self.tmp, "nohash.msi")
        shutil.copy(self.base, src)
        subprocess.run(["msibuild", src, "-q", "DROP TABLE `MsiFileHash`"], check=True, capture_output=True)
        self.assertNotIn("MsiFileHash", msipatch._list_tables(src))
        dst, _ = self._add(src)
        self.assertEqual(len(_tables(dst, "MsiFileHash")), 1)

    def test_signature_removed(self):
        src = os.path.join(self.tmp, "signed.msi")
        shutil.copy(self.base, src)
        sig = os.path.join(self.tmp, "sig.bin")
        open(sig, "wb").write(b"x")
        subprocess.run(["msibuild", src, "-a", "\x05DigitalSignature", sig], check=True, capture_output=True)
        self.assertTrue(msipatch.describe(src)["signed"])
        dst, res = self._add(src)
        self.assertTrue(res.signature_removed)
        self.assertFalse(msipatch.describe(dst)["signed"])

    def test_not_an_msi(self):
        bad = os.path.join(self.tmp, "bad.msi")
        open(bad, "wb").write(b"not an msi")
        with self.assertRaises(msipatch.MsiError):
            self._add(bad)


SAMPLES = os.path.join(HERE, "..", "samples")


@unittest.skipUnless(os.path.isdir(SAMPLES) and shutil.which("gcab") and shutil.which("gsf")
                     and os.environ.get("MSIRB_MSITOOLS_DIR"),
                     "нужны samples/, gsf и MSIRB_MSITOOLS_DIR (пропатченный msitools)")
class RealPackageTest(unittest.TestCase):
    """Настоящий пакет Aspia Host: ImportSettings должен переключиться на вшитый файл, а всё
    остальное (вложенные storages, порядок строк таблиц) — остаться нетронутым."""

    def test_import_settings_redirected(self):
        msis = [f for f in os.listdir(SAMPLES) if f.lower().endswith(".msi")]
        if not msis:
            self.skipTest("в samples/ нет .msi")
        src = os.path.join(SAMPLES, msis[0])
        payload = os.path.join(SAMPLES, "aspia-host.json")
        if not os.path.isfile(payload):
            self.skipTest("в samples/ нет aspia-host.json")
        wd = tempfile.mkdtemp()
        try:
            dst = os.path.join(wd, "out.msi")
            res = msipatch.add_import_file(src, dst, payload, "aspia-host.json", wd)
            self.assertIn('[TempFolder]aspia-host.json', res.command)

            def inner(p):
                out = subprocess.run(["gsf", "list", p], capture_output=True).stdout.decode("utf-8", "replace")
                return sorted(l.split(None, 3)[-1] for l in out.splitlines()[1:] if "/" in l)

            self.assertEqual(inner(src), inner(dst))                # вложенные storages не тронуты

            def clsids(p):
                return {e["name"]: e["clsid"] for e in oledir.read_dir(p) if e["type"] in (1, 5)}
            self.assertEqual(clsids(src), clsids(dst))
            self.assertIn("82100c0000000000c000000000000046", clsids(dst).values())

            # строки всех таблиц упорядочены по первичному ключу (иначе Windows: ошибка 2211)
            self.assertEqual(msicheck.unsorted_tables(dst, msipatch._tool("msiinfo"), msipatch._tool_env()), [])
        finally:
            shutil.rmtree(wd, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
