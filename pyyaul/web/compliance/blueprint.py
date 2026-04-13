"""
Reusable Flask blueprint for lightweight compliance review and action-item tracking.
"""

from datetime import date
from urllib.parse import urlparse

import flask


PRIVILEGE_COMPLIANCE_PATH = ('sudo', 'compliance')
PRIVILEGE_COMPLIANCE_READ = PRIVILEGE_COMPLIANCE_READ_PATH = ('sudo', 'compliance', 'read')
PRIVILEGE_COMPLIANCE_WRITE = PRIVILEGE_COMPLIANCE_WRITE_PATH = ('sudo', 'compliance', 'write')


class BlueprintContext:

    def __init__(
            self,
            blueprint_name: str,
            blueprint_import_name: str,
            dbModelContext,
            authBlueprintContext,
            post_rate_max_requests: int = 20,
            post_rate_window_seconds: float = 60,
    ):
        self.blueprint = flask.Blueprint(
            blueprint_name,
            __name__,
            template_folder='templates',
            static_folder='static',
            url_prefix=f'/{blueprint_name}',
        )
        self.dbModelContext = dbModelContext
        self.authBlueprintContext = authBlueprintContext
        self.post_rate_max_requests = int(post_rate_max_requests)
        self.post_rate_window_seconds = float(post_rate_window_seconds)

        self.blueprint.route('/', methods=('GET',))(self._secure_route(self.page_index))
        self.blueprint.route('/reviews', methods=('GET', 'POST'))(self._secure_route(self.page_reviewList, rate_limit_post=True))
        self.blueprint.route('/reviews/create', methods=('GET', 'POST'))(self._secure_route(self.page_reviewCreate, rate_limit_post=True))
        self.blueprint.route('/reviews/<int:review_id>', methods=('GET', 'POST'))(self._secure_route(self.page_reviewDetail, rate_limit_post=True))
        self.blueprint.route('/reviews/<int:review_id>/findings/create', methods=('GET', 'POST'))(self._secure_route(self.page_findingCreate, rate_limit_post=True))
        self.blueprint.route('/action-items', methods=('GET', 'POST'))(self._secure_route(self.page_actionItemList, rate_limit_post=True))
        self.blueprint.route('/action-items/create', methods=('GET', 'POST'))(self._secure_route(self.page_actionItemCreate, rate_limit_post=True))
        self.blueprint.route('/action-items/<int:action_item_id>', methods=('GET',))(self._secure_route(self.page_actionItemDetail))
        self.blueprint.route('/action-items/<int:action_item_id>/update', methods=('GET', 'POST'))(self._secure_route(self.page_actionItemUpdate, rate_limit_post=True))
        self.blueprint.route('/action-items/<int:action_item_id>/resolve', methods=('POST',))(self._secure_route(self.page_actionItemResolve, rate_limit_post=True))

    def _secure_route(self, func, rate_limit_post: bool = False):
        wrapped = self.authBlueprintContext.authSessionRequired(func, True)
        if rate_limit_post:
            wrapped = self.authBlueprintContext.userRateLimit(
                self.post_rate_max_requests,
                self.post_rate_window_seconds,
            )(wrapped, True)
        return wrapped

    def _current_actor(self, authsession_session_record):
        display_name = getattr(authsession_session_record, 'wolc_authaccounts__user__name_display', None)
        username = getattr(authsession_session_record, 'wolc_authaccounts__user__username', None)
        return {
            'id': getattr(authsession_session_record, 'wolc_authaccounts__user__id', None),
            'username': username,
            'display_name': username if display_name in (None, '') else display_name,
            'session_id': getattr(authsession_session_record, 'wolc_authsession__session__id', None),
        }

    def _privilege_allow(self, authsession_session_record, privilege_path, log: bool = False) -> bool:
        actor = self._current_actor(authsession_session_record)
        return bool(self.authBlueprintContext.dbModelContext.authaccounts_user_allowPrivilege_read(
            actor['id'],
            privilege_path,
            session_id=actor['session_id'] if log else None,
        ))

    def _privilege_require(self, authsession_session_record, privilege_path) -> None:
        if not self._privilege_allow(authsession_session_record, privilege_path, log=True):
            flask.abort(403)

    def _review_topics(self):
        return [item.value for item in self.dbModelContext.dbSchema.ReviewTopic]

    def _finding_severities(self):
        return [item.value for item in self.dbModelContext.dbSchema.FindingSeverity]

    def _action_statuses(self):
        return [item.value for item in self.dbModelContext.dbSchema.ActionItemStatus]

    def _action_update_types(self):
        return [
            self.dbModelContext.dbSchema.ActionItemUpdateType.Progress.value,
            self.dbModelContext.dbSchema.ActionItemUpdateType.Comment.value,
            self.dbModelContext.dbSchema.ActionItemUpdateType.LinkedIssue.value,
            self.dbModelContext.dbSchema.ActionItemUpdateType.Reopened.value,
        ]

    @staticmethod
    def _field_required(field_name: str, raw_value) -> str:
        value = (raw_value or '').strip()
        if value == '':
            raise ValueError(f'ERROR `{field_name}` must be provided.')
        return value

    def _github_issue_details_parse(self, raw_url: str):
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

    def _template_context_base(self, authsession_session_record):
        return {
            'authsession_session_record': authsession_session_record,
            'caller_can_write': self._privilege_allow(authsession_session_record, PRIVILEGE_COMPLIANCE_WRITE_PATH),
            'review_topics': self._review_topics(),
            'finding_severities': self._finding_severities(),
            'action_item_statuses': self._action_statuses(),
            'action_item_update_types': self._action_update_types(),
        }

    def page_index(self, _auth_authsession_session_record):
        self._privilege_require(_auth_authsession_session_record, PRIVILEGE_COMPLIANCE_READ_PATH)
        recent_reviews = self.dbModelContext.reviews_read(limit=5)
        open_action_items = [
            record
            for record in self.dbModelContext.action_items_read(include_resolved=False)
            if record.status != self.dbModelContext.dbSchema.ActionItemStatus.WontFix.value
        ]
        return flask.render_template(
            'compliance/index.html',
            **self._template_context_base(_auth_authsession_session_record),
            recent_reviews=recent_reviews,
            open_action_items=open_action_items[:8],
        )

    def page_reviewList(self, _auth_authsession_session_record):
        self._privilege_require(_auth_authsession_session_record, PRIVILEGE_COMPLIANCE_READ_PATH)
        if flask.request.method == 'POST':
            action = flask.request.form.get('action')
            review_id = flask.request.form.get('review_id')
            if action == 'create':
                return flask.redirect(flask.url_for(f'{self.blueprint.name}.page_reviewCreate'))
            if action == 'view' and review_id is not None:
                return flask.redirect(flask.url_for(f'{self.blueprint.name}.page_reviewDetail', review_id=review_id))
        return flask.render_template(
            'compliance/reviewList.html',
            **self._template_context_base(_auth_authsession_session_record),
            reviews=self.dbModelContext.reviews_read(),
        )

    def page_reviewCreate(self, _auth_authsession_session_record):
        self._privilege_require(_auth_authsession_session_record, PRIVILEGE_COMPLIANCE_WRITE_PATH)
        actor = self._current_actor(_auth_authsession_session_record)
        if flask.request.method == 'POST':
            title = self._field_required('title', flask.request.form.get('title'))
            review_date = date.fromisoformat(self._field_required('review_date', flask.request.form.get('review_date')))
            topic = self._field_required('topic', flask.request.form.get('topic'))
            scope = self._field_required('scope', flask.request.form.get('scope'))
            notes = (flask.request.form.get('notes') or '').strip() or None
            if topic not in self._review_topics():
                raise ValueError(f'ERROR Unsupported review topic: {topic!r}')
            review_record = self.dbModelContext.review_create(
                title=title,
                review_date=review_date,
                topic=topic,
                scope=scope,
                creator_user_id=actor['id'],
                notes=notes,
            )
            return flask.redirect(flask.url_for(f'{self.blueprint.name}.page_reviewDetail', review_id=review_record.id))
        return flask.render_template(
            'compliance/reviewCreate.html',
            **self._template_context_base(_auth_authsession_session_record),
            today_iso=date.today().isoformat(),
        )

    def page_reviewDetail(self, review_id: int, _auth_authsession_session_record):
        self._privilege_require(
            _auth_authsession_session_record,
            PRIVILEGE_COMPLIANCE_WRITE_PATH if flask.request.method == 'POST' else PRIVILEGE_COMPLIANCE_READ_PATH,
        )
        review_record = self.dbModelContext.review_readByID(review_id)
        if flask.request.method == 'POST' and flask.request.form.get('action') == 'complete':
            self.dbModelContext.review_complete(
                review_id,
                notes=(flask.request.form.get('notes') or '').strip() or None,
            )
            return flask.redirect(flask.url_for(f'{self.blueprint.name}.page_reviewDetail', review_id=review_id))
        finding_records = self.dbModelContext.findings_readByReviewID(review_id)
        finding_action_items = {
            finding_record.id: self.dbModelContext.action_items_readByFindingID(finding_record.id)
            for finding_record in finding_records
        }
        return flask.render_template(
            'compliance/reviewDetail.html',
            **self._template_context_base(_auth_authsession_session_record),
            review=review_record,
            findings=finding_records,
            finding_action_items=finding_action_items,
        )

    def page_findingCreate(self, review_id: int, _auth_authsession_session_record):
        self._privilege_require(_auth_authsession_session_record, PRIVILEGE_COMPLIANCE_WRITE_PATH)
        review_record = self.dbModelContext.review_readByID(review_id)
        if flask.request.method == 'POST':
            severity = self._field_required('severity', flask.request.form.get('severity'))
            title = self._field_required('title', flask.request.form.get('title'))
            description = self._field_required('description', flask.request.form.get('description'))
            if severity not in self._finding_severities():
                raise ValueError(f'ERROR Unsupported finding severity: {severity!r}')
            self.dbModelContext.finding_create(
                review_id=review_id,
                severity=severity,
                title=title,
                description=description,
                creator_user_id=self._current_actor(_auth_authsession_session_record)['id'],
            )
            return flask.redirect(flask.url_for(f'{self.blueprint.name}.page_reviewDetail', review_id=review_id))
        return flask.render_template(
            'compliance/findingCreate.html',
            **self._template_context_base(_auth_authsession_session_record),
            review=review_record,
        )

    def page_actionItemList(self, _auth_authsession_session_record):
        self._privilege_require(_auth_authsession_session_record, PRIVILEGE_COMPLIANCE_READ_PATH)
        if flask.request.method == 'POST':
            action = flask.request.form.get('action')
            action_item_id = flask.request.form.get('action_item_id')
            if action == 'create':
                return flask.redirect(flask.url_for(f'{self.blueprint.name}.page_actionItemCreate'))
            if action == 'view' and action_item_id is not None:
                return flask.redirect(flask.url_for(f'{self.blueprint.name}.page_actionItemDetail', action_item_id=action_item_id))
        return flask.render_template(
            'compliance/actionItemList.html',
            **self._template_context_base(_auth_authsession_session_record),
            action_items=self.dbModelContext.action_items_read(),
        )

    def page_actionItemCreate(self, _auth_authsession_session_record):
        self._privilege_require(_auth_authsession_session_record, PRIVILEGE_COMPLIANCE_WRITE_PATH)
        review_id = flask.request.values.get('review_id')
        finding_id = flask.request.values.get('finding_id')
        review_record = None
        finding_record = None
        if finding_id not in (None, ''):
            finding_record = self.dbModelContext.finding_readByID(int(finding_id))
            review_record = self.dbModelContext.review_readByID(finding_record.review_id)
        elif review_id not in (None, ''):
            review_record = self.dbModelContext.review_readByID(int(review_id))
        if flask.request.method == 'POST':
            title = self._field_required('title', flask.request.form.get('title'))
            description = self._field_required('description', flask.request.form.get('description'))
            github_repo, github_issue_number, github_issue_url = self._github_issue_details_parse(
                flask.request.form.get('github_issue_url', '')
            )
            action_item_record = self.dbModelContext.action_item_create(
                title=title,
                description=description,
                creator_user_id=self._current_actor(_auth_authsession_session_record)['id'],
                finding_id=None if finding_id in (None, '') else int(finding_id),
                github_repo=github_repo,
                github_issue_number=github_issue_number,
                github_issue_url=github_issue_url,
            )
            return flask.redirect(
                flask.url_for(f'{self.blueprint.name}.page_actionItemDetail', action_item_id=action_item_record.id)
            )
        return flask.render_template(
            'compliance/actionItemCreate.html',
            **self._template_context_base(_auth_authsession_session_record),
            review=review_record,
            finding=finding_record,
            selected_finding_id=None if finding_id in (None, '') else int(finding_id),
        )

    def page_actionItemDetail(self, action_item_id: int, _auth_authsession_session_record):
        self._privilege_require(_auth_authsession_session_record, PRIVILEGE_COMPLIANCE_READ_PATH)
        action_item_record = self.dbModelContext.action_item_readByID(action_item_id)
        finding_record = None
        review_record = None
        if action_item_record.finding_id is not None:
            finding_record = self.dbModelContext.finding_readByID(action_item_record.finding_id)
            review_record = self.dbModelContext.review_readByID(finding_record.review_id)
        return flask.render_template(
            'compliance/actionItemDetail.html',
            **self._template_context_base(_auth_authsession_session_record),
            action_item=action_item_record,
            action_item_updates=self.dbModelContext.action_item_updates_readByActionItemID(action_item_id),
            finding=finding_record,
            review=review_record,
        )

    def page_actionItemUpdate(self, action_item_id: int, _auth_authsession_session_record):
        self._privilege_require(_auth_authsession_session_record, PRIVILEGE_COMPLIANCE_WRITE_PATH)
        action_item_record = self.dbModelContext.action_item_readByID(action_item_id)
        if flask.request.method == 'POST':
            update_type = self._field_required('update_type', flask.request.form.get('update_type'))
            notes = self._field_required('notes', flask.request.form.get('notes'))
            if update_type not in self._action_update_types():
                raise ValueError(f'ERROR Unsupported update type: {update_type!r}')
            if update_type == self.dbModelContext.dbSchema.ActionItemUpdateType.Reopened.value:
                self.dbModelContext.action_item_status_set(
                    action_item_id,
                    self.dbModelContext.dbSchema.ActionItemStatus.Open.value,
                    resolver_user_id=None,
                )
            elif action_item_record.status == self.dbModelContext.dbSchema.ActionItemStatus.Open.value:
                self.dbModelContext.action_item_status_set(
                    action_item_id,
                    self.dbModelContext.dbSchema.ActionItemStatus.InProgress.value,
                    resolver_user_id=None,
                )
            self.dbModelContext.action_item_update_create(
                action_item_id=action_item_id,
                update_type=update_type,
                notes=notes,
                creator_user_id=self._current_actor(_auth_authsession_session_record)['id'],
            )
            return flask.redirect(flask.url_for(f'{self.blueprint.name}.page_actionItemDetail', action_item_id=action_item_id))
        return flask.render_template(
            'compliance/actionItemUpdate.html',
            **self._template_context_base(_auth_authsession_session_record),
            action_item=action_item_record,
        )

    def page_actionItemResolve(self, action_item_id: int, _auth_authsession_session_record):
        self._privilege_require(_auth_authsession_session_record, PRIVILEGE_COMPLIANCE_WRITE_PATH)
        notes = (flask.request.form.get('notes') or '').strip()
        self.dbModelContext.action_item_status_set(
            action_item_id,
            self.dbModelContext.dbSchema.ActionItemStatus.Resolved.value,
            resolver_user_id=self._current_actor(_auth_authsession_session_record)['id'],
        )
        self.dbModelContext.action_item_update_create(
            action_item_id=action_item_id,
            update_type=self.dbModelContext.dbSchema.ActionItemUpdateType.Resolved.value,
            notes=notes if notes != '' else 'Action item resolved.',
            creator_user_id=self._current_actor(_auth_authsession_session_record)['id'],
        )
        return flask.redirect(flask.url_for(f'{self.blueprint.name}.page_actionItemDetail', action_item_id=action_item_id))
