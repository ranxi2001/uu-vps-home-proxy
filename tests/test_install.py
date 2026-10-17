import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from uu_vps_proxy import __version__


class InstallTests(unittest.TestCase):
    def test_install_upgrade_and_cli_are_independent(self):
        source = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory() as directory:
            prefix = Path(directory) / 'prefix with spaces'
            for _ in range(2):
                result = subprocess.run([sys.executable, str(source / 'install.py'), '--prefix', str(prefix)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                entry = prefix / 'bin/uu-vps-proxy'
                result = subprocess.run([str(entry), '--version'], capture_output=True, text=True, cwd='/')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), __version__)
            result = subprocess.run([str(entry), '--help'], capture_output=True, text=True, cwd='/')
            self.assertIn('configure', result.stdout)
            self.assertIn('bypass', (prefix / 'share/uu-vps-home-proxy/current/uu_vps_proxy/manager.py').read_text())
