"""Safety and architecture classifications for read-only CBS preflight."""
import unittest
from scripts.netfx481_cbs_operation_preflight import preflight, summarize_many


def mum(arch, interior=""):
    return (f'<assembly xmlns="urn:schemas-microsoft-com:asm.v3">'
            f'<assemblyIdentity processorArchitecture="{arch}" name="PRIVATE"/>'
            f'{interior}</assembly>').encode()


class CbsOperationPreflightTests(unittest.TestCase):
    def test_amd64_and_dependency_census(self):
        raw = mum("amd64", '<package><update name="SECRET"/>'
                  '<parent name="SECRET"/><dependency name="SECRET"/>'
                  '<registryValue name="SECRET"/><file name="SECRET"/></package>')
        report = preflight(raw)
        self.assertEqual(report["target_arch"], "amd64")
        self.assertEqual(report["root_identity_arch"], "amd64")
        self.assertEqual(report["updates"], 1)
        self.assertEqual(report["installer_assembly"], 0)
        self.assertEqual(report["parents"], 1)
        self.assertEqual(report["dependencies"], 1)
        self.assertFalse(report["safe_to_apply"])
        self.assertNotIn("SECRET", str(report))
        self.assertNotIn("PRIVATE", str(report))

    def test_mixed_architecture_is_not_amd64_only(self):
        report = preflight(mum("amd64", '<assemblyIdentity processorArchitecture="x86"/>'))
        self.assertEqual(report["target_arch"], "MIXED")
        self.assertEqual(report["root_identity_arch"], "amd64")
        self.assertFalse(report["safe_to_apply"])

    def test_malformed_dtd_and_wrong_root_are_rejected(self):
        for raw in (b"<!DOCTYPE assembly><assembly/>",
                    b"<!ENTITY x 'foo'><assembly/>",
                    b"<assembly><broken>",
                    b"<package/>", b""):
            self.assertEqual(preflight(raw)["status"], "INVALID")

    def test_unsupported_actions_remain_non_installable(self):
        report = preflight(mum("amd64", "<customInformation/><serviceData/>"))
        self.assertEqual(report["unsupported_operations"], 2)
        self.assertEqual(report["custom_information"], 1)
        self.assertEqual(report["other_unsupported"], 1)
        self.assertFalse(report["safe_to_apply"])

    def test_aggregate_no_identifiers(self):
        report = summarize_many([mum("amd64"), mum("x86"), b"bad"])
        self.assertEqual((report["parsed"], report["invalid"]), (2, 1))
        self.assertEqual(report["amd64_only"], 1)
        self.assertEqual(report["root_amd64"], 1)
        self.assertEqual(report["root_x86"], 1)
        self.assertEqual(report["root_amd64_updates"], 0)
        self.assertEqual(report["installer_assembly"], 0)
        self.assertEqual(report["unsupported_operations"], 0)
        scoped = summarize_many([mum("amd64", "<package><update/><installerAssembly/></package>"),
                                 mum("arm64", "<package><update/><update/></package>")])
        self.assertEqual(scoped["updates"], 3)
        self.assertEqual(scoped["root_amd64_updates"], 1)
        self.assertEqual(scoped["root_amd64_unsupported"], 1)
        self.assertEqual(scoped["installer_assembly"], 1)
        self.assertFalse(report["safe_to_apply"])
        self.assertNotIn("PRIVATE", str(report))


if __name__ == "__main__":
    unittest.main()
