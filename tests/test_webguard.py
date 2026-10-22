
import unittest
from unittest.mock import MagicMock, patch

from scripts.webguard import assess_url


def fake_response(
    status_code=200,
    headers=None,
    cookies=None,
):
    """Build a simulated HTTP response without network access."""
    response = MagicMock()
    response.status_code = status_code
    response.headers = headers or {
        "Content-Type": "text/html; charset=utf-8"
    }
    response.raw.headers.getlist.return_value = cookies or []
    return response


class WebGuardTests(unittest.TestCase):

    @patch("scripts.webguard.requests.get")
    def test_https_target_returns_structured_report(self, mock_get):
        mock_get.return_value = fake_response()

        report = assess_url("https://test.example")

        self.assertEqual(report["tool"], "WebGuard")
        self.assertEqual(report["http_status"], 200)
        self.assertIn("summary", report)
        self.assertIn("findings", report)
        mock_get.assert_called_once()

    @patch("scripts.webguard.requests.get")
    def test_missing_security_headers_are_review_findings(self, mock_get):
        mock_get.return_value = fake_response()

        report = assess_url("https://test.example")

        csp = next(
            item for item in report["findings"]
            if item["title"] == "Content-Security-Policy was not observed"
        )

        self.assertEqual(csp["status"], "REVIEW")
        self.assertIn("remediation", csp)

    @patch("scripts.webguard.requests.get")
    def test_http_url_produces_transport_warning(self, mock_get):
        mock_get.return_value = fake_response()

        report = assess_url("http://test.example")

        transport = next(
            item for item in report["findings"]
            if item["id"] == "WG-001"
        )

        self.assertEqual(transport["severity"], "MEDIUM")
        self.assertEqual(transport["status"], "OBSERVED")

    @patch("scripts.webguard.requests.get")
    def test_cookie_missing_attributes_are_flagged(self, mock_get):
        mock_get.return_value = fake_response(
            cookies=["sessionid=sample; Path=/"]
        )

        report = assess_url("https://test.example")

        cookie = next(
            item for item in report["findings"]
            if item["title"] == "Cookie 1 attribute review"
        )

        self.assertEqual(cookie["status"], "REVIEW")
        self.assertIn("Secure", cookie["evidence"])
        self.assertIn("HttpOnly", cookie["evidence"])
        self.assertIn("SameSite", cookie["evidence"])

    @patch("scripts.webguard.requests.get")
    def test_cookie_with_security_attributes_is_observed(self, mock_get):
        mock_get.return_value = fake_response(
            cookies=[
                "sessionid=sample; Secure; HttpOnly; SameSite=Lax; Path=/"
            ]
        )

        report = assess_url("https://test.example")

        cookie = next(
            item for item in report["findings"]
            if item["title"] == "Cookie 1 attribute review"
        )

        self.assertEqual(cookie["status"], "OBSERVED")

    @patch("scripts.webguard.requests.get")
    def test_invalid_scheme_is_rejected_before_request(self, mock_get):
        with self.assertRaises(ValueError):
            assess_url("ftp://test.example")

        mock_get.assert_not_called()


if __name__ == "__main__":
    unittest.main()
