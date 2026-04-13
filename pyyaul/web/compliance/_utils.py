"""
Shared compliance helpers that are safe to import from Flask and CLI modules.
"""

from urllib.parse import urlparse


def _parse_github_issue_url(raw_url: str):
    """Return (github_repo, github_issue_number, github_issue_url) from a GitHub issue URL."""
    url = (raw_url or '').strip()
    if url == '':
        return (None, None, None)
    parsed = urlparse(url)
    path_parts = [part for part in parsed.path.split('/') if part]
    if parsed.netloc.lower() == 'github.com' and len(path_parts) >= 4 and path_parts[2] == 'issues':
        try:
            issue_number = int(path_parts[3])
        except ValueError:
            issue_number = None
        return (f'{path_parts[0]}/{path_parts[1]}', issue_number, url)
    return (None, None, url)
