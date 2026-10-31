import unittest

from phishguard import analyze_text, inspect_url


def rules(url):
    return {item["rule"] for item in inspect_url(url)["findings"]}


class PhishGuardTests(unittest.TestCase):
    def test_http_flagged(self):
        self.assertIn("not_https", rules("http://example.org"))

    def test_embedded_credentials_flagged(self):
        self.assertIn("embedded_credentials", rules("https://user:pass@example.org"))

    def test_message_urgency(self):
        result = analyze_text("Act now, account will be suspended")
        self.assertTrue(result["message_indicators"]["urgency_language"])

    def test_legitimate_brand_domain_not_flagged(self):
        self.assertNotIn("possible_brand_impersonation", rules("https://www.microsoft.com"))

    def test_brand_bait_subdomain_flagged(self):
        self.assertIn("possible_brand_impersonation", rules("https://microsoft-login.example.org"))

    def test_ipv4_host_flagged(self):
        self.assertIn("ip_address_host", rules("https://192.0.2.10/login"))

    def test_ipv6_host_supported(self):
        result = inspect_url("https://[2001:db8::1]/login")
        self.assertEqual(result["host"], "2001:db8::1")
        self.assertIn("ip_address_host", rules("https://[2001:db8::1]/login"))

    def test_invalid_port_rejected(self):
        self.assertIn("invalid_url", rules("https://example.org:99999"))

    def test_malformed_ipv6_rejected(self):
        self.assertIn("invalid_url", rules("https://[2001:db8::1"))

    def test_punycode_detected(self):
        self.assertIn("punycode_domain", rules("https://xn--e1afmkfd.example"))

    def test_url_shortener_detected(self):
        self.assertIn("url_shortener", rules("https://bit.ly/example"))

    def test_suspicious_keyword_in_encoded_path(self):
        self.assertIn("suspicious_url_keywords", rules("https://example.org/%6Cogin"))

    def test_non_url_text_has_no_urls(self):
        self.assertEqual(analyze_text("Hello, how are you?")["urls"], [])

    def test_non_string_input_is_safe(self):
        self.assertEqual(inspect_url(None)["risk_score"], 30)
        self.assertEqual(analyze_text(None)["urls"], [])


if __name__ == "__main__":
    unittest.main()
