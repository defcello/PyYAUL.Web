"""
Reusable CLI base class for adding entries to the compliance audit log.

Consumers instantiate ComplianceCLIBase with a DBModelContext and call run().
No Flask dependency — works standalone from any script that can reach the DB.
"""

import argparse
import datetime
import sys
from urllib.parse import urlparse


def _parse_github_url(raw_url: str):
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


class ComplianceCLIBase:

    def __init__(self, dbModelContext, default_user_id: int = 1):
        self.dbModelContext = dbModelContext
        self.default_user_id = int(default_user_id)

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(self, args=None) -> int:
        """Parse args (or sys.argv[1:] if None), dispatch subcommand. Returns exit code."""
        parser = self._build_parser()
        parsed = parser.parse_args(args)
        if not hasattr(parsed, 'func'):
            parser.print_help()
            return 1
        try:
            return parsed.func(parsed)
        except Exception as exc:
            print(f'ERROR: {exc}', file=sys.stderr)
            return 1

    # ------------------------------------------------------------------
    # Parser construction
    # ------------------------------------------------------------------

    def _build_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            description='Compliance audit log CLI — add or view compliance entries.',
        )
        sub = parser.add_subparsers(metavar='COMMAND')

        # ---- log ----
        p_log = sub.add_parser(
            'log',
            help='Create a completed compliance review entry (with optional finding and action item).',
        )
        p_log.add_argument('--title', required=True,
                           help='Short title for this review entry.')
        p_log.add_argument('--topic', required=True,
                           choices=['security', 'accessibility', 'legal', 'performance', 'privacy', 'other'],
                           help='Review topic.')
        p_log.add_argument('--date', default=None,
                           help='Review date (YYYY-MM-DD). Defaults to today.')
        p_log.add_argument('--scope', default=None,
                           help='Scope description. Defaults to --title.')
        p_log.add_argument('--notes', default=None,
                           help='Free-form notes attached to the review.')
        p_log.add_argument('--severity',
                           choices=['info', 'warning', 'critical'], default=None,
                           help='If given, attach a finding with this severity.')
        p_log.add_argument('--finding-title', default=None, dest='finding_title',
                           help='Finding title. Defaults to --title. Only used with --severity.')
        p_log.add_argument('--finding-description', default=None, dest='finding_description',
                           help='Finding description. Defaults to finding title. Only used with --severity.')
        p_log.add_argument('--action-item-title', default=None, dest='action_item_title',
                           help='Create an action item linked to the finding. Requires --severity.')
        p_log.add_argument('--action-item-description', default=None, dest='action_item_description',
                           help='Action item description. Defaults to action item title.')
        p_log.add_argument('--github-issue-url', default=None, dest='github_issue_url',
                           help='GitHub issue URL for the action item (parsed to extract repo + number).')
        p_log.add_argument('--user-id', type=int, default=None, dest='user_id',
                           help=f'creator_user_id for all created records. Defaults to {self.default_user_id}.')
        p_log.add_argument('--dry-run', action='store_true', dest='dry_run',
                           help='Print what would be created without writing to the database.')
        p_log.set_defaults(func=self._cmd_log)

        # ---- list-reviews ----
        p_list = sub.add_parser(
            'list-reviews',
            help='List recent compliance reviews.',
        )
        p_list.add_argument('--limit', type=int, default=10,
                            help='Maximum number of reviews to show (default: 10).')
        p_list.set_defaults(func=self._cmd_list_reviews)

        # ---- show-review ----
        p_show = sub.add_parser(
            'show-review',
            help='Show full details of a review including findings and action items.',
        )
        p_show.add_argument('review_id', type=int,
                            help='ID of the review to display.')
        p_show.set_defaults(func=self._cmd_show_review)

        return parser

    # ------------------------------------------------------------------
    # Subcommand implementations
    # ------------------------------------------------------------------

    def _cmd_log(self, parsed) -> int:
        # Validate cross-argument constraints
        if parsed.action_item_title and not parsed.severity:
            print('ERROR: --action-item-title requires --severity.', file=sys.stderr)
            return 2

        # Resolve defaults
        user_id = parsed.user_id if parsed.user_id is not None else self.default_user_id
        review_date = datetime.date.fromisoformat(parsed.date) if parsed.date else datetime.date.today()
        scope = parsed.scope or parsed.title
        finding_title = parsed.finding_title or parsed.title
        finding_description = parsed.finding_description or finding_title
        action_item_description = parsed.action_item_description or parsed.action_item_title

        if parsed.dry_run:
            print(f'[DRY RUN] Would create review:')
            print(f'  title:   {parsed.title}')
            print(f'  topic:   {parsed.topic}')
            print(f'  date:    {review_date}')
            print(f'  scope:   {scope}')
            print(f'  notes:   {parsed.notes or "(none)"}')
            print(f'  user_id: {user_id}')
            print(f'[DRY RUN] Would immediately complete review.')
            if parsed.severity:
                print(f'[DRY RUN] Would create finding:')
                print(f'  severity:    {parsed.severity}')
                print(f'  title:       {finding_title}')
                print(f'  description: {finding_description}')
                if parsed.action_item_title:
                    github_repo, github_issue_number, github_issue_url = _parse_github_url(
                        parsed.github_issue_url or '')
                    print(f'[DRY RUN] Would create action item:')
                    print(f'  title:       {parsed.action_item_title}')
                    print(f'  description: {action_item_description}')
                    if github_repo:
                        print(f'  GitHub:      {github_repo} #{github_issue_number}')
                    elif github_issue_url:
                        print(f'  GitHub URL:  {github_issue_url}')
                else:
                    print(f'[DRY RUN] No action item (--action-item-title not provided).')
            else:
                print(f'[DRY RUN] No finding (--severity not provided).')
            return 0

        # Write to DB
        review = self.dbModelContext.review_create(
            title=parsed.title,
            review_date=review_date,
            topic=parsed.topic,
            scope=scope,
            creator_user_id=user_id,
            notes=parsed.notes,
        )
        self.dbModelContext.review_complete(review.id)
        print(f'Created review #{review.id}: {parsed.title} ({parsed.topic}, {review_date}) [completed]')

        if parsed.severity:
            finding = self.dbModelContext.finding_create(
                review_id=review.id,
                severity=parsed.severity,
                title=finding_title,
                description=finding_description,
                creator_user_id=user_id,
            )
            print(f'  Created finding #{finding.id}: [{parsed.severity}] {finding_title}')

            if parsed.action_item_title:
                github_repo, github_issue_number, github_issue_url = _parse_github_url(
                    parsed.github_issue_url or '')
                action_item = self.dbModelContext.action_item_create(
                    title=parsed.action_item_title,
                    description=action_item_description,
                    creator_user_id=user_id,
                    finding_id=finding.id,
                    github_repo=github_repo,
                    github_issue_number=github_issue_number,
                    github_issue_url=github_issue_url,
                )
                print(f'  Created action item #{action_item.id}: {parsed.action_item_title}')
                if github_repo:
                    print(f'    GitHub: {github_repo} #{github_issue_number}')

        print(f'  creator_user_id: {user_id}')
        return 0

    def _cmd_list_reviews(self, parsed) -> int:
        reviews = self.dbModelContext.reviews_read(limit=parsed.limit)
        if not reviews:
            print('No compliance reviews found.')
            return 0
        id_w = max(len(str(r.id)) for r in reviews)
        id_w = max(id_w, 2)
        print(f'{"ID":<{id_w}}  {"Date":<10}  {"Topic":<13}  {"Status":<11}  Title')
        print(f'{"-"*id_w}  {"-"*10}  {"-"*13}  {"-"*11}  {"-"*40}')
        for r in reviews:
            print(f'{r.id:<{id_w}}  {str(r.review_date):<10}  {r.topic:<13}  {r.status:<11}  {r.title}')
        return 0

    def _cmd_show_review(self, parsed) -> int:
        try:
            review = self.dbModelContext.review_readByID(parsed.review_id)
        except ValueError as exc:
            print(f'ERROR: {exc}', file=sys.stderr)
            return 1

        print(f'Review #{review.id}')
        print(f'  Title:   {review.title}')
        print(f'  Topic:   {review.topic}')
        print(f'  Scope:   {review.scope}')
        print(f'  Date:    {review.review_date}')
        print(f'  Status:  {review.status}')
        print(f'  Notes:   {review.notes or "(none)"}')

        findings = self.dbModelContext.findings_readByReviewID(review.id)
        if not findings:
            print()
            print('  Findings: (none)')
            return 0

        print()
        print('  Findings:')
        for f in findings:
            print(f'    #{f.id} [{f.severity}] {f.title}')
            if f.description:
                print(f'      Description: {f.description}')
            action_items = self.dbModelContext.action_items_readByFindingID(f.id)
            if action_items:
                print(f'      Action Items:')
                for ai in action_items:
                    print(f'        #{ai.id} [{ai.status}] {ai.title}')
                    if ai.github_repo:
                        print(f'          GitHub: {ai.github_repo} #{ai.github_issue_number}')
                    elif ai.github_issue_url:
                        print(f'          GitHub URL: {ai.github_issue_url}')
        return 0
