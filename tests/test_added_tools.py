import csv
import io
import unittest
from pathlib import Path
from unittest.mock import patch

from app import app, enhanced_model, extract_features
from domain_checks import (
    DomainCheckError,
    _public_addresses,
    lookup_whois,
    normalize_domain,
)
from enhanced_features import FEATURE_COUNT
from enhanced_features import extract_enhanced_features
from ip_lookup import IPLookupError, lookup_public_ip
from known_phishing import (
    _url_key,
    check_known_phishing_url,
    load_known_phishing_urls,
)
from url_analysis import analyze_redirect_chain, check_lookalike_domain


class AddedToolTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_original_feature_function_is_still_available(self):
        self.assertEqual(len(extract_features("https://example.com")[0]), 15)

    def test_original_scanner_still_works_with_the_bundled_classifier(self):
        response = self.client.post(
            "/api/scan/url",
            json={"url": "https://example.com"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("confidence", response.json["data"])

    def test_known_phishing_csv_contains_labeled_urls_and_matches_normalized_url(self):
        entries = load_known_phishing_urls()
        self.assertGreater(len(entries), 0)
        with open("datasets/known_phishing_urls.csv", newline="", encoding="utf-8") as data_file:
            listed_url = next(csv.DictReader(data_file))["url"]
        result = check_known_phishing_url(listed_url, entries)
        self.assertTrue(result["listed"])
        self.assertEqual(result["database"], "Local labeled URL dataset")
        self.assertFalse(check_known_phishing_url("https://not-listed.invalid", entries)["listed"])
        normalized_entries = {_url_key("http://example.com/login"): "test source"}
        self.assertTrue(check_known_phishing_url("https://example.com/login/", normalized_entries)["listed"])

    def test_known_link_match_is_included_in_regular_scan_response(self):
        with open("datasets/known_phishing_urls.csv", newline="", encoding="utf-8") as data_file:
            url = next(csv.DictReader(data_file))["url"]
        response = self.client.post("/api/scan/url", json={"url": url})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json["data"]["known_phishing"]["listed"])

    def test_dashboard_shows_the_new_additive_tools(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        for label in (b"Enhanced URL", b"Domain", b"Speed"):
            self.assertIn(label, response.data)
        self.assertIn(b"The AI model decides the verdict.", response.data)
        self.assertIn(b'role="tablist"', response.data)
        self.assertIn(b'aria-live="polite"', response.data)
        self.assertIn(b"Analyze redirect chain", response.data)
        self.assertIn(b"Check lookalike domain", response.data)
        self.assertIn(b"Manual public IP lookup", response.data)
        self.assertIn(b"The entered IP is sent to ipwho.is.", response.data)

    def test_menu_information_pages_are_not_blank(self):
        pages = {
            "/why": b"The problem",
            "/how-it-works": b"URL Scanner",
            "/limitations": b"No detector is perfect",
        }
        for path, expected in pages.items():
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)
                self.assertIn(expected, response.data)

    def test_about_page_shows_student_supervisor_then_university_without_quick_links(self):
        response = self.client.get("/about")
        self.assertEqual(response.status_code, 200)
        for expected in (
            b"The People's University of Bangladesh",
            b"Nur Tarikul Islam",
            b"Computer Science &amp; Engineering",
            b"Md. Masud Reza",
            b"github.com/unknownowl007",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, response.data)
        self.assertNotIn(b"Quick Links", response.data)
        page = response.data.decode("utf-8")
        self.assertLess(page.index('aria-labelledby="student-heading"'), page.index('aria-labelledby="supervisor-heading"'))
        self.assertLess(page.index('aria-labelledby="supervisor-heading"'), page.index('aria-labelledby="university-heading"'))
        supervisor = page.split('aria-labelledby="supervisor-heading"', 1)[1].split("</section>", 1)[0]
        self.assertIn("Dean, Faculty of Applied Science", supervisor)
        self.assertNotIn("<dt>Department</dt>", supervisor)

    def test_vercel_bundle_keeps_runtime_assets_out_of_the_function(self):
        import json

        config = json.loads(Path("vercel.json").read_text(encoding="utf-8"))
        exclusions = config["functions"]["app.py"]["excludeFiles"]
        self.assertIn("model/phishing_model.pkl", exclusions)
        self.assertIn("datasets/Training.csv", exclusions)
        self.assertIn("public/static/**", exclusions)

    def test_app_serves_public_static_assets(self):
        response = self.client.get("/static/style.css")
        self.addCleanup(response.close)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b".dashboard", response.data)

    def test_scan_history_page_is_available_from_navigation(self):
        response = self.client.get("/history")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Scan History", response.data)
        self.assertIn(b"clear-history-btn", response.data)
        self.assertIn(b"Scan History", response.data)

    def test_speed_test_uses_internet_test_server_not_app_transfer_routes(self):
        script = Path("public/static/script.js").read_text(encoding="utf-8")
        self.assertIn("https://speed.cloudflare.com/__down", script)
        self.assertIn("https://speed.cloudflare.com/__up", script)
        self.assertIn("['Upload'", script)

    def test_enhanced_classifier_uses_the_additional_feature_set(self):
        self.assertIsNotNone(enhanced_model)
        self.assertEqual(enhanced_model.n_features_in_, FEATURE_COUNT)
        response = self.client.post(
            "/api/scan/url/enhanced",
            json={"url": "https://example.com/login"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["data"]["feature_count"], FEATURE_COUNT)
        self.assertIn("explanation", response.json["data"])

    def test_standard_url_scan_includes_model_explanation_for_report(self):
        response = self.client.post("/api/scan/url", json={"url": "https://example.com/login"})
        self.assertEqual(response.status_code, 200)
        explanation = response.json["data"]["explanation"]
        self.assertEqual(explanation["method"], "random_forest_path_contribution")
        self.assertIn("signals", explanation)

    def test_brand_lookalike_check_flags_typos_but_not_official_domain(self):
        result = check_lookalike_domain("https://paypa1.com/login")
        self.assertTrue(result["suspicious"])
        self.assertEqual(result["matches"][0]["brand"], "paypal")
        self.assertFalse(check_lookalike_domain("https://www.google.com")["suspicious"])

    def test_lookalike_api_validates_and_returns_match_details(self):
        response = self.client.post("/api/analyze/lookalike", json={"domain": "paypa1.com"})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json["data"]["suspicious"])
        invalid = self.client.post("/api/analyze/lookalike", json={"domain": "localhost"})
        self.assertEqual(invalid.status_code, 400)

    def test_manual_ip_lookup_accepts_only_public_ip_addresses(self):
        with patch("ip_lookup.requests.get") as get:
            with self.assertRaises(ValueError):
                lookup_public_ip("192.168.1.1")
            with self.assertRaises(ValueError):
                lookup_public_ip("example.com")
        get.assert_not_called()

    def test_ip_lookup_parses_location_and_network_fields(self):
        response = unittest.mock.Mock()
        response.json.return_value = {
            "success": True,
            "ip": "8.8.8.8",
            "type": "IPv4",
            "country": "United States",
            "region": "Virginia",
            "city": "Ashburn",
            "latitude": 39.03,
            "longitude": -77.5,
            "connection": {
                "isp": "Example ISP",
                "org": "Example Network",
                "asn": 15169,
            },
        }
        response.raise_for_status.return_value = None
        with patch("ip_lookup.requests.get", return_value=response) as get:
            result = lookup_public_ip("8.8.8.8")
        self.assertEqual(result["isp"], "Example ISP")
        self.assertEqual(result["asn"], 15169)
        self.assertEqual(result["provider"], "ipwho.is")
        get.assert_called_once()
        self.assertIn("8.8.8.8", get.call_args.args[0])

    def test_manual_ip_lookup_api_validates_and_returns_provider_data(self):
        expected = {"ip": "8.8.8.8", "country": "United States", "provider": "ipwho.is"}
        with patch("app.lookup_public_ip", return_value=expected) as lookup:
            response = self.client.post("/api/domain/ip-lookup", json={"ip": "8.8.8.8"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["data"], expected)
        lookup.assert_called_once_with("8.8.8.8")

        invalid = self.client.post("/api/domain/ip-lookup", json={"ip": "127.0.0.1"})
        self.assertEqual(invalid.status_code, 400)

        with patch("app.lookup_public_ip", side_effect=IPLookupError("The service is unavailable.")):
            unavailable = self.client.post("/api/domain/ip-lookup", json={"ip": "8.8.8.8"})
        self.assertEqual(unavailable.status_code, 502)

    def test_redirect_endpoint_reports_safe_redirect_analysis(self):
        expected = {
            "chain": [{"url": "https://example.com", "hostname": "example.com", "status": 200}],
            "final_url": "https://example.com",
            "redirect_count": 0,
        }
        with patch("app.analyze_redirect_chain", return_value=expected) as analyze:
            response = self.client.post("/api/analyze/redirects", json={"url": "https://example.com"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["data"], expected)
        analyze.assert_called_once_with("https://example.com")

    def test_redirect_analyzer_refuses_credentials_and_nonstandard_ports(self):
        with self.assertRaises(ValueError):
            analyze_redirect_chain("https://user@example.com")
        with self.assertRaises(ValueError):
            analyze_redirect_chain("https://example.com:8443")

    def test_redirect_analyzer_follows_chain_and_reports_terminal_url(self):
        with patch("url_analysis._fetch_status_and_location", side_effect=[
            (302, "/continue"),
            (200, None),
        ]):
            with patch("url_analysis._public_host_addresses", return_value=[]):
                result = analyze_redirect_chain("https://example.com/start")
        self.assertEqual(result["redirect_count"], 1)
        self.assertEqual(result["final_url"], "https://example.com/continue")
        self.assertEqual(result["chain"][0]["status"], 302)

    def test_redirect_analyzer_blocks_private_and_local_destinations(self):
        private_answer = (2, 1, 6, "", ("127.0.0.1", 443))
        with patch("url_analysis.socket.getaddrinfo", return_value=[private_answer]):
            with self.assertRaises(DomainCheckError):
                analyze_redirect_chain("https://example.com")

    def test_redirect_analyzer_revalidates_each_redirect_destination(self):
        public_answer = (2, 1, 6, "", ("8.8.8.8", 80))
        private_answer = (2, 1, 6, "", ("127.0.0.1", 80))

        class FakeSocket:
            def settimeout(self, _):
                pass

            def connect(self, _):
                pass

            def sendall(self, _):
                pass

            def makefile(self, _):
                return io.BytesIO(b"HTTP/1.1 302 Found\r\nLocation: http://internal.test/\r\n\r\n")

            def close(self):
                pass

        with patch("url_analysis.socket.getaddrinfo", side_effect=[
            [public_answer],
            [private_answer],
        ]), patch("url_analysis.socket.socket", return_value=FakeSocket()) as make_socket:
            with self.assertRaises(DomainCheckError):
                analyze_redirect_chain("http://example.com")
        make_socket.assert_called_once()

    def test_model_features_ignore_scheme_and_trailing_root_slash(self):
        self.assertEqual(
            extract_enhanced_features("http://example.com"),
            extract_enhanced_features("https://example.com/"),
        )
        http = self.client.post("/api/scan/url", json={"url": "http://example.com"})
        https = self.client.post("/api/scan/url", json={"url": "https://example.com"})
        self.assertEqual(http.json["data"]["is_phishing"], https.json["data"]["is_phishing"])
        self.assertEqual(http.json["data"]["confidence"], https.json["data"]["confidence"])
        self.assertFalse(https.json["data"]["is_phishing"])

    def test_url_verdict_is_model_driven_not_local_list_driven(self):
        from unittest.mock import MagicMock, patch

        fake_model = MagicMock()
        fake_model.predict.return_value = [0]
        fake_model.predict_proba.return_value = [[0.9, 0.1]]
        with patch("app.enhanced_model", fake_model), \
                patch("app.known_phishing_urls", {"example.com": "test CSV source"}):
            response = self.client.post("/api/scan/url", json={"url": "https://example.com"})

        self.assertFalse(response.json["data"]["is_phishing"])
        self.assertTrue(response.json["data"]["known_phishing"]["listed"])

    def test_domain_validation_and_private_address_guard(self):
        self.assertEqual(normalize_domain("https://ExAmPlE.com/path"), "example.com")
        with self.assertRaises(ValueError):
            normalize_domain("https://user@example.com")

        private_answer = (2, 1, 6, "", ("127.0.0.1", 443))
        with patch("domain_checks.socket.getaddrinfo", return_value=[private_answer]):
            with self.assertRaises(DomainCheckError):
                _public_addresses("example.com")

    def test_ssl_endpoint_accepts_domain_and_returns_data(self):
        expected = {"valid": True, "hostname": "example.com"}
        with patch("app.check_ssl_certificate", return_value=expected) as check:
            response = self.client.post(
                "/api/domain/ssl",
                json={"domain": "https://Example.com"},
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["data"], expected)
        check.assert_called_once_with("example.com")

    def test_whois_result_parsing(self):
        bootstrap = unittest.mock.Mock()
        bootstrap.status_code = 200
        bootstrap.json.return_value = {
            "services": [[["com"], ["https://rdap.verisign.com/com/v1/"]]]
        }
        bootstrap.raise_for_status.return_value = None
        record = {
            "ldhName": "EXAMPLE.COM",
            "entities": [{
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]],
            }],
            "events": [{"eventAction": "registration", "eventDate": "2000-01-01T00:00:00Z"}],
            "status": ["active"],
        }
        response = unittest.mock.Mock()
        response.status_code = 200
        response.json.return_value = record
        response.raise_for_status.return_value = None
        with patch("domain_checks.requests.get", side_effect=[bootstrap, response]) as get:
            result = lookup_whois("example.com")
        self.assertEqual(result["registrar"], "Example Registrar")
        self.assertEqual(result["created_at"], "2000-01-01T00:00:00Z")
        self.assertTrue(get.call_args_list[1].args[0].startswith("https://rdap.verisign.com/com/v1/domain/"))

    def test_whois_route_reports_unavailable_service(self):
        with patch("app.lookup_whois", side_effect=DomainCheckError("The service is unavailable.")):
            response = self.client.post("/api/domain/whois", json={"domain": "example.com"})
        self.assertEqual(response.status_code, 502)
        self.assertIn("unavailable", response.json["message"])

    def test_speed_transfer_size_is_bounded(self):
        download = self.client.get("/api/speed/download")
        self.assertEqual(download.status_code, 200)
        self.assertEqual(len(download.data), 4 * 1024 * 1024)

        upload = self.client.post(
            "/api/speed/upload",
            data=b"x" * 1024,
            content_type="application/octet-stream",
        )
        self.assertEqual(upload.status_code, 200)
        self.assertEqual(upload.json["bytes_received"], 1024)

        too_large = self.client.post(
            "/api/speed/upload",
            data=b"x" * (2 * 1024 * 1024 + 1),
            content_type="application/octet-stream",
        )
        self.assertEqual(too_large.status_code, 413)


if __name__ == "__main__":
    unittest.main()
