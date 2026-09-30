"""Тесты app/portable_build.py: python3 -m unittest tests/test_portable_build.py
Критично: формат хвоста должен точно совпадать с тем, что читает portable/launcher.c —
несовпадение на один байт полностью ломает извлечение MSI на стороне Windows."""
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "app"))
import portable_build as pb  # noqa: E402


class BuildPortableExeTest(unittest.TestCase):
    def test_concatenates_stub_and_msi_with_correct_trailer(self):
        stub_bytes = b"STUB" * 100
        msi_bytes = b"MSI-PAYLOAD-BYTES" * 5000   # достаточно большой, проверить чтение по кускам

        with tempfile.TemporaryDirectory() as d:
            stub_path = Path(d) / "stub.exe"
            msi_path = Path(d) / "package.msi"
            dest_path = Path(d) / "out.exe"
            stub_path.write_bytes(stub_bytes)
            msi_path.write_bytes(msi_bytes)

            pb.build_portable_exe(stub_path, msi_path, dest_path)
            result = dest_path.read_bytes()

        # хвост: 8 байт длины (little-endian) + 8 байт магии — именно так его читает launcher.c
        trailer = result[-16:]
        msi_len = struct.unpack("<Q", trailer[:8])[0]
        magic = trailer[8:]

        self.assertEqual(magic, pb.MAGIC)
        self.assertEqual(magic, b"ASPIAPX1")
        self.assertEqual(msi_len, len(msi_bytes))
        self.assertEqual(result[:len(stub_bytes)], stub_bytes)
        self.assertEqual(result[len(stub_bytes):len(stub_bytes) + len(msi_bytes)], msi_bytes)
        self.assertEqual(len(result), len(stub_bytes) + len(msi_bytes) + 16)

    def test_missing_stub_raises_portable_build_error(self):
        with tempfile.TemporaryDirectory() as d:
            msi_path = Path(d) / "package.msi"
            msi_path.write_bytes(b"x")
            with self.assertRaises(pb.PortableBuildError):
                pb.build_portable_exe(Path(d) / "no-such-stub.exe", msi_path, Path(d) / "out.exe")


if __name__ == "__main__":
    unittest.main()
