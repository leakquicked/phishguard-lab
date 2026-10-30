import unittest
from phishguard import inspect_url, analyze_text

class PhishGuardTests(unittest.TestCase):
    def test_http_flagged(self):
        self.assertIn("not_https", [x["rule"] for x in inspect_url("http://example.org")["findings"]])
    def test_embedded_credentials_flagged(self):
        self.assertIn("embedded_credentials", [x["rule"] for x in inspect_url("https://user:pass@example.org")["findings"]])
    def test_message_urgency(self):
        self.assertTrue(analyze_text("Act now, account will be suspended")["message_indicators"]["urgency_language"])
if __name__ == "__main__": unittest.main()
