"""Safe Mac-to-Windows SOLIDWORKS connection profiles."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from scripts.solidworks_remote_mac import rdp_profile, validate_host, write_profile

class MacRemoteTests(unittest.TestCase):
    def test_accept_private_lan_and_tailscale(self):
        for host in ("192.168.1.25", "10.12.0.4", "172.20.1.8",
                     "100.100.55.4", "myworkstation", "myworkstation.local",
                     "workstation.tail123.ts.net"):
            with self.subTest(host=host):
                self.assertEqual(validate_host(host), host)

    def test_reject_public_ip_and_untrusted_hostname(self):
        for host in ("8.8.8.8", "1.1.1.1", "https://example.com",
                     "public.example.com", "localhost:3389", "127.0.0.1",
                     " 192.168.1.5", "host\r\nusername:s:bad", "host/name",
                     "169.254.0.2"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                validate_host(host)

    def test_profile_requires_authentication_without_secret_or_file_shares(self):
        x = rdp_profile("100.100.10.5")
        for fragment in ("full address:s:100.100.10.5",
                         "authentication level:i:2", "enablecredsspsupport:i:1",
                         "prompt for credentials:i:1", "drivestoredirect:s:"):
            self.assertIn(fragment, x)
        self.assertNotIn("password", x.lower())
        self.assertNotIn("username:s:", x.lower())
        self.assertIn("\r\n", x)

    def test_write_new_profile_and_never_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "SOLIDWORKS.rdp"
            write_profile("192.168.0.2", path)
            self.assertEqual(path.read_bytes().count(b"full address:s:192.168.0.2"), 1)
            with self.assertRaises(FileExistsError):
                write_profile("192.168.0.5", path)
            if os.name != "nt":
                self.assertEqual(path.stat().st_mode & 0o077, 0)

    def test_cli_rejects_public_host(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "bad.rdp"
            run = subprocess.run([sys.executable, "-m", "scripts.solidworks_remote_mac",
                                  "--host", "8.8.8.8", "--output", str(path)],
                                 capture_output=True, text=True)
            self.assertNotEqual(run.returncode, 0)
            self.assertFalse(path.exists())

if __name__ == "__main__":
    unittest.main()
