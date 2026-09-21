import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parents[1] / "services" / "netscaler-adapter"))
sys.path.insert(0, str(Path(__file__).parents[1] / "services" / "signature-sync"))

from app.sync import SyncConfig, parse_mapping, sync_once


class SignatureSyncTests(unittest.TestCase):
    def test_parse_mapping_selects_exact_release_and_build(self):
        mapping = b"""<AppfwSignatures date=\"2026/09/15\"><Signature release=\"14.1\" build=\"0\" version=\"183\" schema_version=\"8\"><sig_file><file>sigs/sig.xml</file><sha1>sigs/sig.xml.sha1</sha1></sig_file></Signature></AppfwSignatures>"""
        result = parse_mapping(mapping, source_url="https://example.test/SignaturesMapping.xml", target_release="14.1", target_build="0")
        self.assertEqual(result["version"], "183")
        self.assertEqual(result["file_url"], "https://example.test/sigs/sig.xml")

    def test_sync_downloads_verifies_and_skips_unchanged_source(self):
        signature = b"""<SignaturesFile><Signatures><SignatureRule id=\"1001\" category=\"sql\" enabled=\"OFF\" actions=\"log,block\"><LogString>SQL injection</LogString></SignatureRule></Signatures></SignaturesFile>"""
        digest = hashlib.sha1(signature).hexdigest().encode("ascii")
        mapping = b"""<AppfwSignatures date=\"2026/09/15\"><Signature release=\"14.1\" build=\"0\" version=\"183\" schema_version=\"8\"><sig_file><file>sigs/sig.xml</file><sha1>sigs/sig.xml.sha1</sha1></sig_file></Signature></AppfwSignatures>"""
        payloads = {
            "https://example.test/SignaturesMapping.xml": mapping,
            "https://example.test/sigs/sig.xml": signature,
            "https://example.test/sigs/sig.xml.sha1": digest,
        }
        calls: list[str] = []

        def fetch(url: str, timeout: int, limit: int) -> bytes:
            calls.append(url)
            return payloads[url]

        with tempfile.TemporaryDirectory() as directory:
            config = SyncConfig(source_url="https://example.test/SignaturesMapping.xml", data_dir=Path(directory))
            first = sync_once(config, fetcher=fetch)
            call_count = len(calls)
            second = sync_once(config, fetcher=fetch)
            index = json.loads((Path(directory) / "upstream/index/latest.json").read_text(encoding="utf-8"))
        self.assertEqual(first["last_result"], "updated")
        self.assertEqual(first["rule_count"], 1)
        self.assertEqual(second["last_result"], "not-modified")
        self.assertEqual(len(calls), call_count + 2)
        self.assertEqual(index["rule_count"], 1)


if __name__ == "__main__":
    unittest.main()
