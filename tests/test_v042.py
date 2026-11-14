# 0.42 Overview numbers link to the list behind them.
import unittest

from tests.helpers import app


class Links(unittest.TestCase):
    def test_kpi_tiles_are_links(self):
        con = app.connect()
        html, _w, _tw = app.overview_kpis(con, app.settings(con))
        for href in ("/ips?days=1", "/ips?days=1&amp;sort=sessions", "/ips?days=7&amp;tag=took-bait", "/ips?days=7", "/files", "/receipt", "/blocklist"):
            self.assertIn('href="%s"' % href, html)
        self.assertEqual(html.count('<a class="kpi'), 7)
        self.assertNotIn('<div class="kpi"', html)
        self.assertNotIn('<div class="kpi ', html)

    def test_week_card_links(self):
        con = app.connect()
        w = {"active": 5, "before": 4, "new_ips": 2, "new_cc": ["SE", "<x>"], "campaigns": 0, "campaign_ips": 0,
             "families": {"Mirai": 3, "Unknown": 1}, "took": 1}
        html = app.week_card(con, w)
        self.assertIn('<a href="/ips?days=7&amp;sort=first">2</a>', html)
        self.assertIn('href="/ips?days=7&amp;cc=SE"', html)
        self.assertIn('href="/ips?days=7&amp;cc=%3Cx%3E"', html)          # attacker data is quoted, never raw
        self.assertNotIn("<x>", html)
        self.assertIn('href="/files?fam=Mirai"', html)
        self.assertIn('<a href="/ips?days=7&amp;tag=took-bait">1</a>', html)


if __name__ == "__main__":
    unittest.main()
