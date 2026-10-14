"""Regression checks for the RootHide jailbreakd logging IPC fallback."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class JailbreakdLoggingTests(unittest.TestCase):
    def test_unsupported_log_message_does_not_abort_daemon(self):
        source = (ROOT / "BaseBin/jailbreakd/src/server.m").read_text(encoding="utf-8")
        self.assertIn("#include <errno.h>", source)
        logging_case = source.split("case JBD_MSG_SYSTEMWIDE_LOG:", 1)[1].split(
            "case JBD_MSG_TEST_CALL:", 1
        )[0]
        self.assertIn('xpc_dictionary_set_int64(reply, "result", -ENOTSUP);', logging_case)
        self.assertNotIn("abort()", logging_case)


if __name__ == "__main__":
    unittest.main()
