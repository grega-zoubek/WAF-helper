import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parents[1] / "services" / "discovery-worker"))

from app.technology_detection import detect_technology_signals


class TechnologyDetectionTests(unittest.TestCase):
    def test_exchange_owa_uses_multiple_specific_signals_and_version(self):
        signals = detect_technology_signals(
            url="https://mail.example.test/owa/auth.owa",
            headers={
                "server": "Microsoft-IIS/10.0",
                "x-owa-version": "15.2.1748.5",
                "content-type": "text/html",
            },
            cookies=["X-OWA-CANARY", "OutlookSession"],
            title="Outlook Web App",
            body="<html><title>Outlook Web App</title><form><input type='password'></form></html>",
        )
        owa = [item for item in signals if item["technology"] == "Microsoft Exchange OWA"]
        self.assertGreaterEqual(len(owa), 3)
        self.assertEqual({item["category"] for item in owa}, {"application-platform"})
        self.assertIn("15.2.1748.5", {item["version"] for item in owa})
        self.assertTrue(any(item["signal_family"] == "url" for item in owa))
        self.assertTrue(any(item["signal_family"] == "cookie" for item in owa))

    def test_wordpress_generator_and_assets_extract_version(self):
        signals = detect_technology_signals(
            url="https://shop.example.test/",
            headers={"content-type": "text/html; charset=utf-8"},
            cookies=["wordpress_logged_in_abc"],
            meta=[{"name": "generator", "content": "WordPress 6.4.3"}],
            assets=[
                "https://shop.example.test/wp-includes/js/jquery.js",
                "https://shop.example.test/wp-content/themes/shop/style.css",
            ],
            body='<link rel="https://api.w.org/" href="/wp-json/">',
        )
        wordpress = [item for item in signals if item["technology"] == "WordPress"]
        self.assertGreaterEqual(len(wordpress), 3)
        self.assertEqual({item["version"] for item in wordpress}, {"6.4.3"})
        self.assertEqual({item["category"] for item in wordpress}, {"cms"})

    def test_drupal_and_magento_markers_are_distinct_products(self):
        drupal = detect_technology_signals(
            url="https://portal.example.test/",
            headers={"content-type": "text/html"},
            meta=[{"name": "generator", "content": "Drupal 10.2.1"}],
            body="var drupalSettings = {};",
        )
        magento = detect_technology_signals(
            url="https://store.example.test/",
            headers={"content-type": "text/html"},
            cookies=["private_content_version", "section_data_ids"],
            body="<script type='text/x-magento-init'>{}</script>",
        )
        self.assertIn("Drupal", {item["technology"] for item in drupal})
        self.assertIn("Magento", {item["technology"] for item in magento})
        self.assertNotIn("WordPress", {item["technology"] for item in drupal + magento})

    def test_outlook_text_without_owa_evidence_is_not_exchange_detection(self):
        signals = detect_technology_signals(
            url="https://news.example.test/outlook-news",
            headers={"content-type": "text/html"},
            title="Outlook product news",
            body="Read our latest outlook on the market.",
        )
        self.assertNotIn("Microsoft Exchange OWA", {item["technology"] for item in signals})

    def test_server_version_is_kept_separate_from_application_platform(self):
        signals = detect_technology_signals(
            url="https://example.test/",
            headers={"server": "Microsoft-IIS/10.0", "content-type": "text/html"},
        )
        iis = next(item for item in signals if item["technology"] == "Microsoft IIS")
        self.assertEqual(iis["category"], "web-server")
        self.assertEqual(iis["version"], "10.0")

    def test_generic_css_icon_name_is_not_laravel_evidence(self):
        signals = detect_technology_signals(
            url="https://shop.example.test/styles.css",
            headers={"content-type": "text/css"},
            body='.icon-laravel:before{content:"\\f147"}',
        )
        self.assertNotIn("Laravel", {item["technology"] for item in signals})

    def test_laravel_session_cookie_is_positive_evidence(self):
        signals = detect_technology_signals(
            url="https://shop.example.test/",
            cookies=["laravel_session"],
        )
        laravel = [item for item in signals if item["technology"] == "Laravel"]
        self.assertEqual(len(laravel), 1)
        self.assertEqual(laravel[0]["signal_family"], "cookie")


if __name__ == "__main__":
    unittest.main()
