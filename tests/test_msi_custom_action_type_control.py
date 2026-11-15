"""Self-authored MSI custom DLL action control, strict no-false-compatibility gates."""
import hashlib
import io
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest import mock

from scripts import msi_custom_action_type_control as control
from scripts.netfx40_msi_custom_type import validate as validate_type


class MsiControlTests(unittest.TestCase):
    def test_self_authored_control_matches_original_wine_action_type(self):
        original = (
            b'0100:trace:msi:ACTION_CustomAction Handling custom action '
            b'L"ServiceTypeControlSentinel" (c01 L"private.dll" L"PRIVATE")\n'
            b'0100:err:msi:execute_script action '
            b'L"ServiceTypeControlSentinel" returned 1603\n'
        )
        process = mock.Mock()
        process.stderr = io.BytesIO(original)
        process.wait.return_value = 67
        with TemporaryDirectory() as td:
            root = Path(td)
            wine = root / "wine"
            wine.write_bytes(b"test fake wine")
            wine.chmod(0o700)
            msi = root / "swcompat_custom_action_type_control.msi"
            msi.write_bytes(b"self-authored MSICONTROL")
            sha = root / "msi-custom-control.sha256"
            sha.write_text(hashlib.sha256(msi.read_bytes()).hexdigest())
            with (
                mock.patch.object(control, "validate_prefix"),
                mock.patch.object(control, "windows_media_path",
                                  return_value="Z:\\SelfAuthored\\MSI.msi"),
                mock.patch.object(control.subprocess, "Popen",
                                  return_value=process) as open_process
            ):
                report = control.inspect(wine, root, msi, sha, timeout=30)
            self.assertTrue(control.validate(report))
            self.assertEqual(report["msi_process"], "NONZERO")
            self.assertEqual(report["custom_action_type"]["status"], "TRACE_MATCHED")
            self.assertEqual(report["custom_action_type"]["family"], "DLL_BINARY")
            self.assertEqual(report["custom_action_type"]["execution"], "DEFERRED")
            self.assertEqual(report["custom_action_type"]["impersonation"], "NO_IMPERSONATE")
            self.assertTrue(validate_type(report["custom_action_type"]))
            for token in ("SelfAuthored", "ServiceTypeControlSentinel", "private.dll"):
                self.assertNotIn(token, str(report))
            self.assertEqual(
                open_process.call_args.kwargs["stderr"], control.subprocess.PIPE)

    def test_rejects_incorrect_msi_hash_and_forged_readiness(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            wine = root / "wine"
            wine.write_bytes(b"wine")
            wine.chmod(0o700)
            msi = root / "swcompat_custom_action_type_control.msi"
            msi.write_bytes(b"control bytes")
            sha = root / "msi-custom-control.sha256"
            sha.write_text("a" * 64)
            with mock.patch.object(control, "validate_prefix"):
                with self.assertRaises(ValueError):
                    control.inspect(wine, root, msi, sha)
        report = {
            "status": "MEASURED",
            "msi_process": "NONZERO",
            "custom_action_type": control.parse(
                b'0100:err:msi:execute_script action L"ServiceTypeControlSentinel" returned 1603\n'),
            "native_microsoft_clr": False,
            "solidworks_compatibility": "NOT_DEMONSTRATED",
        }
        self.assertTrue(control.validate(report))
        self.assertFalse(control.validate(dict(report, native_microsoft_clr=True)))
        self.assertFalse(control.validate(dict(report, private_path="/secrets")))
        self.assertFalse(control.validate(dict(report, msi_process="WORKING_CAD")))
        self.assertFalse(control.validate(dict(report, solidworks_compatibility="READY")))


if __name__ == "__main__":
    unittest.main()
