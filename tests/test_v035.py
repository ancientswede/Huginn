# 0.35 The Help page and tag tooltips.
import re, unittest

from tests.helpers import app


class Help(unittest.TestCase):
    def test_every_tag_is_explained(self):
        # Every tag score_and_tags can set, plus research and the manual flags, has a text in TAG_HELP.
        _s, tags = app.score_and_tags(500, 50, 50, 50, 1, 1, 1, ["ftp", "mysql"], 120, ["ssh", "telnet"], True, True, True, "exploit robots")
        _s, tags2 = app.score_and_tags(1, 0, 0, 0, 0, 0, 0, [], 0, [], web="probe")
        for t in set(tags.split(",")) | set(tags2.split(",")) | {"research", "block", "allow", "human-like"}:
            self.assertTrue(app.TAG_HELP.get(t), t)
        for t in app.TAG_CLASS:
            self.assertTrue(app.tag_title(t) or t in ("server", "camera", "nas", "router"), t)

    def test_tooltip_on_tags(self):
        html = app.tag_html("shell,dropper,unknown-tag")
        self.assertIn('title="%s"' % app.esc(app.TAG_HELP["shell"]), html)
        self.assertIn('<span class="tag ">unknown-tag</span>', html)

    def test_page(self):
        html = app.v_help()
        self.assertIn("<h1>Help</h1>", html)
        self.assertIsNone(re.search(r"\sstyle=", html))
        for t in ("took-bait", "sshole-probe", "research", "novel", "Left at once", "Time wasted"):
            self.assertIn(t, html)
        self.assertIn(app.esc(app.SCORE_HELP), html)
        self.assertIn("href='/help'", app.page("x", ""))


if __name__ == "__main__":
    unittest.main()
