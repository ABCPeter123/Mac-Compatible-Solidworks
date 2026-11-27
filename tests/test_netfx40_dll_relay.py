import unittest
from scripts.netfx40_dll_relay import Capture

class RelayTests(unittest.TestCase):
    def test_only_failed_dll_scope_counts_public_api_returns(self):
        cap = Capture()
        for line in (
            b"0024:Call msi.__wine_msi_call_dll_function(SECRET)",
            b"0024:Ret  advapi32.RegOpenKeyExW() retval=00000005 ret=11111111",
            b"0024:Ret  kernelbase.GetProcAddress() retval=00000000 ret=11111111",
            b"0030:Ret  advapi32.RegOpenKeyExW() retval=00000002 ret=22222222",
            b"0024:Ret  msi.__wine_msi_call_dll_function() retval=00000643 ret=11111111",
            b"0024:Call msi.__wine_msi_call_dll_function(OTHER)",
            b"0024:Ret  advapi32.RegOpenKeyExW() retval=00000000 ret=11111111",
            b"0024:Ret  msi.__wine_msi_call_dll_function() retval=00000000 ret=11111111",
        ):
            cap.feed(line)
        r = cap.report(True)
        self.assertEqual(r["status"], "FAILED_DLL_SCOPE_OBSERVED")
        self.assertEqual(r["completed_scopes"], 2)
        self.assertEqual(r["failed_scopes"], 1)
        self.assertEqual(r["failed_scope_api_returns"]["RegOpenKeyExW"], {"success": 0, "failure": 1})
        self.assertEqual(r["failed_scope_api_returns"]["GetProcAddress"]["failure"], 1)
        for private in ("SECRET", "OTHER", "0024", "11111111"):
            self.assertNotIn(private, str(r))

    def test_incomplete_capture_never_exports_api_counts(self):
        cap = Capture()
        cap.feed(b"0024:Call msi.__wine_msi_call_dll_function(x)")
        cap.feed(b"0024:Ret  advapi32.RegOpenKeyExW() retval=00000005 ret=0")
        self.assertEqual(cap.report(True)["status"], "INCOMPLETE")
        self.assertEqual(cap.report(False)["failed_scope_api_returns"], {})
        self.assertEqual(Capture().report(True)["status"], "NO_DLL_SCOPE")
