"""Tests for the dry-run-only WUSA integration."""
from pathlib import Path
import unittest
from scripts.patch_wusa_ipd_dryrun import patch_main, OLD_IPD, OLD_INSTALL, OLD_DWORD, git_blob, patch_manifest, patch_file_names, patch_full_preflight
from scripts.netfx481_ipd_wusa_dryrun import parse_packet, CATEGORIES


class WusaDryRunTests(unittest.TestCase):
    def test_patch_removes_apply_and_preserves_dryrun(self):
        fixture = "\n".join(["WINE_DEFAULT_DEBUG_CHANNEL(wusa);", OLD_IPD,
                             "    HKEY root, subkey;", "    install_updates(state, TRUE);",
                             OLD_INSTALL, "static BOOL install_registry_dword(", OLD_DWORD,
                             "    if (!(output = malloc(length))) return NULL;",
                             "        *p++ = wcstoul(number, 0, 16);",
                             "static void restart_as_x86_64(void)",
                             "int __cdecl wmain(int argc, WCHAR *argv[])"])
        modified = patch_main(fixture)
        self.assertIn("temp_path = swcompat_stage;", modified)
        self.assertIn("install_updates(state, TRUE)", modified)
        self.assertNotIn("install_updates(state, FALSE)", modified)
        self.assertNotIn("restart_as_x86_64", modified)
        self.assertIn("swcompat_parse_dword(registrykv->value, &value)", modified)
        self.assertNotIn("wcstoul(registrykv->value_type", modified)
        self.assertIn("swcompat_hex_digit(number[0]) < 0", modified)
        self.assertIn("swcompat_numeric_selftest()", modified)
        with self.assertRaises(ValueError):
            patch_main(modified)

    def test_explicit_com_abi_conversion(self):
        calls = "IXMLDOMElement_getAttribute(root, name, &value);\nIXMLDOMNode_Release(node);\n" * 9
        converted = patch_manifest(calls)
        self.assertIn("root->lpVtbl->getAttribute(root, name, &value)", converted)
        self.assertIn("node->lpVtbl->Release(node)", converted)
        with self.assertRaises(ValueError):
            patch_manifest("IXMLDOMNode_Release(node);")

    def test_renamed_payload_is_same_assembly_only(self):
        main = "\n".join([
            "static BOOL install_files_copy(",
            "    int csidl = 0;",
            "    if (!(target = path_combine(target_path, fileop->source))) goto error;",
            "    if (!(source = path_combine(source_path, fileop->source))) goto error;",
            "if (!(ret = PathFileExistsW(source)))",
        ])
        manifest = "\n".join([
            "    free(entry->source);\n    free(entry->target);",
            '    if (!(entry->source = get_xml_attribute(root, L"sourceName"))) goto error;',
        ])
        header = "    WCHAR       *source;\n    WCHAR       *target;"
        m, x, h = patch_file_names(main, manifest, header)
        self.assertIn("path_combine(target_path, fileop->name)", m)
        self.assertIn("path_combine(source_path, fileop->name)", m)
        self.assertIn("GetFileAttributesW(source) == INVALID_FILE_ATTRIBUTES", m)
        self.assertIn("swcompat_regular_file(source)", m)
        self.assertIn("FILE_ATTRIBUTE_REPARSE_POINT", m)
        self.assertIn('L"assembly.empty"', m)
        self.assertIn("p == start || p[-1]", m)
        self.assertIn("swcompat_counts[14]++", m)
        self.assertIn('get_xml_attribute(root, L"name")', x)
        self.assertIn("free(entry->name)", x)
        self.assertIn("WCHAR       *name;", h)

    def test_full_preflight_does_not_replace_dependency_traversal(self):
        text = "    /* perform dry run */\n    if (!install_updates(state, TRUE)) goto done;"
        patched = patch_full_preflight(text)
        self.assertIn("install_files(item, TRUE)", patched)
        self.assertIn("install_registry(item, TRUE)", patched)
        self.assertIn("if (!install_updates(state, TRUE)) goto done;", patched)
        self.assertNotIn("install_updates(state, FALSE)", patched)

    def test_git_blob_identity(self):
        self.assertEqual(git_blob(b""), "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391")

    def packet(self, result="PASS", count=1):
        return "\n".join(["SWCOMPAT_IPD_DRYRUN_SCHEMA=1",
                          "SWCOMPAT_IPD_DRYRUN_RESULT=" + result,
                          "SWCOMPAT_IPD_DRYRUN_IPD=" + str(count)] +
                         [f"SWCOMPAT_IPD_DRYRUN_C{i}=0" for i in range(len(CATEGORIES))]).encode()

    def test_allowlisted_result(self):
        report = parse_packet(self.packet(), 0)
        self.assertEqual(report["dryrun"], "PASS")
        self.assertFalse(report["servicing_performed"])
        self.assertEqual(parse_packet(self.packet("FAIL", 0), 1)["dryrun"], "FAIL")
        for data, code in [(self.packet(), 1), (self.packet(count=0), 0),
                           (self.packet() + b"\nprivate path", 0),
                           (self.packet() + b"\nSWCOMPAT_IPD_DRYRUN_C0=4", 0)]:
            with self.assertRaises(ValueError):
                parse_packet(data, code)


if __name__ == "__main__":
    unittest.main()
