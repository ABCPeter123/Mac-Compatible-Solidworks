"""Synthetic controls for the read-only manifest inventory."""
from pathlib import Path
import tempfile
import unittest
from scripts.netfx481_ipd_manifest_audit import audit_members

IDENT = 'name="component" processorArchitecture="amd64" language="neutral" publicKeyToken="test" version="1.0.0.0"'
OTHER = IDENT.replace('name="component"', 'name="absent"')


class ManifestAuditTests(unittest.TestCase):
    def test_identity_file_registry_and_dependency_categories(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            members = {}
            def write(name, data):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                members[name] = path
            write("one.manifest", (f'<assembly xmlns="urn:schemas-microsoft-com:asm.v3">'
                  f'<assemblyIdentity {IDENT}/><dependency><dependentAssembly dependencyType="install">'
                  f'<assemblyIdentity {OTHER}/></dependentAssembly></dependency>'
                  '<file sourceName="present.dll" destinationPath="$(runtime.system32)"/>'
                  '<file sourceName="absent.dll" destinationPath="$(unknown)"/>'
                  '<registryKeys><registryKey keyName="test"><registryValue valueType="REG_DWORD" value="0x1234"/>'
                  '<registryValue valueType="REG_DWORD" value="0xGG"/>'
                  '<registryValue valueType="REG_BINARY" value="ABZ0"/>'
                  '</registryKey></registryKeys></assembly>').encode())
            write("one/present.dll", b"self-authored")
            write("two.manifest", b"DCM\x01test")
            write("bad.mum", b"<!DOCTYPE a [<!ENTITY x 'test'>]><a/>")
            report = audit_members(members)
            c = report["counts"]
            self.assertEqual(c["root_documents"], 3)
            self.assertEqual(c["xml"], 1)
            self.assertEqual(c["dcm"], 1)
            self.assertEqual(c["unsafe_xml"], 1)
            self.assertEqual(c["dependency_absent"], 1)
            self.assertEqual(c["missing_wusa_source"], 1)
            self.assertEqual(c["unknown_destination_expression"], 1)
            self.assertEqual(c["invalid_dword_value"], 1)
            self.assertEqual(c["invalid_binary_value"], 1)
            self.assertFalse(report["servicing_performed"])
            self.assertNotIn("present.dll", str(report))
            self.assertNotIn("0x1234", str(report))


    def test_source_alias_and_reachable_dependency_classification(self):
        from scripts.netfx481_ipd_manifest_audit import identity
        import xml.etree.ElementTree as ET
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            manifest = root / "one.manifest"
            manifest.write_text(
                f'<assembly><assemblyIdentity {IDENT}/>'
                f'<dependency><dependentAssembly><assemblyIdentity {OTHER}/></dependentAssembly></dependency>'
                '<file sourceName="not-real.dll" name="actual.dll" destinationPath="$(runtime.system32)"/>'
                '<registryKeys><registryKey keyName="test">'
                '<registryValue valueType="REG_SZ" value="$(runtime.testpath)\\private"/>'
                '</registryKey></registryKeys></assembly>')
            payload = root / "payload"
            payload.write_bytes(b"fixture")
            report = audit_members({"one.manifest": manifest, "one/actual.dll": payload},
                                   [identity(ET.fromstring(f'<assemblyIdentity {IDENT}/>'))])
            self.assertEqual(report["missing_source_categories"], {"same_assembly_destination_name": 1})
            self.assertEqual(report["missing_dependency_categories"], {"name_not_packaged": 1})
            self.assertEqual(report["unknown_runtime_tokens"], {"runtime.testpath": 1})
            self.assertEqual(report["reachable"], {"resolved": 1, "unresolved": 1, "update_roots": 1})
            self.assertNotIn("private", str(report))


if __name__ == "__main__":
    unittest.main()
