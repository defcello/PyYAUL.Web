from unittest import TestCase

from pyyaul.web.compliance._utils import _parse_github_issue_url


class Test_parse_github_issue_url(TestCase):

    def test_parses_issue_url(self):
        self.assertEqual(
            ('defcello/PyYAUL.Web', 18, 'https://github.com/defcello/PyYAUL.Web/issues/18'),
            _parse_github_issue_url(' https://github.com/defcello/PyYAUL.Web/issues/18 '),
        )

    def test_keeps_non_issue_url_without_repo_details(self):
        self.assertEqual(
            (None, None, 'https://github.com/defcello/PyYAUL.Web/pull/18'),
            _parse_github_issue_url('https://github.com/defcello/PyYAUL.Web/pull/18'),
        )

    def test_rejects_non_numeric_issue_number(self):
        self.assertEqual(
            ('defcello/PyYAUL.Web', None, 'https://github.com/defcello/PyYAUL.Web/issues/not-a-number'),
            _parse_github_issue_url('https://github.com/defcello/PyYAUL.Web/issues/not-a-number'),
        )
