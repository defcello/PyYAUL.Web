"""
Database access layer for the reusable compliance audit log module.
"""

from inspect import isclass

import sqlalchemy
from sqlalchemy import insert, select, update

from .schema.vLatest import Schema


def _sqlalchemy_recordDetachFromSession(ormRecord, session):
    mapper = sqlalchemy.inspection.inspect(ormRecord).mapper
    for column in mapper.columns:
        getattr(ormRecord, column.name)
    session.expunge(ormRecord)
    return ormRecord


def _table_columns(table_or_model):
    return getattr(table_or_model, 'c', table_or_model)


class DBModelContext:

    def __init__(self, dbORM_RO, dbORM_RW, dbSchema: Schema):
        if isclass(dbSchema):
            raise ValueError('ERROR `dbSchema` should be an instance, not a class.')
        self.dbORM_RO = dbORM_RO
        self.dbORM_RW = dbORM_RW
        self.dbSchema = dbSchema

    @property
    def _review_table_name(self):
        return f'{self.dbSchema.schema_name}.table_compliance_review'

    @property
    def _finding_table_name(self):
        return f'{self.dbSchema.schema_name}.table_compliance_finding'

    @property
    def _action_item_table_name(self):
        return f'{self.dbSchema.schema_name}.table_action_item'

    @property
    def _action_item_update_table_name(self):
        return f'{self.dbSchema.schema_name}.table_action_item_update'

    def review_create(
            self,
            title: str,
            review_date,
            topic: str,
            scope: str,
            creator_user_id: int,
            notes: str | None = None,
    ):
        with self.dbORM_RW.session() as dbSession:
            table_review = self.dbORM_RW.tables[self._review_table_name]
            record = dbSession.execute(
                insert(table_review).returning(table_review),
                {
                    'title': title,
                    'review_date': review_date,
                    'topic': topic,
                    'scope': scope,
                    'status': self.dbSchema.ReviewStatus.InProgress.value,
                    'creator_user_id': creator_user_id,
                    'notes': notes,
                },
            ).scalar_one()
            dbSession.commit()
            return _sqlalchemy_recordDetachFromSession(record, dbSession)

    def reviews_read(self, limit: int | None = None):
        with self.dbORM_RO.session() as dbSession:
            table_review = self.dbORM_RO.tables[self._review_table_name]
            table_review_columns = _table_columns(table_review)
            stmt = select(table_review).order_by(table_review_columns.review_date.desc(), table_review_columns.id.desc())
            if limit is not None:
                stmt = stmt.limit(int(limit))
            records = dbSession.execute(stmt).scalars().all()
            return [_sqlalchemy_recordDetachFromSession(record, dbSession) for record in records]

    def review_readByID(self, review_id: int):
        with self.dbORM_RO.session() as dbSession:
            table_review = self.dbORM_RO.tables[self._review_table_name]
            table_review_columns = _table_columns(table_review)
            record = dbSession.execute(
                select(table_review).where(table_review_columns.id == int(review_id))
            ).scalar_one_or_none()
            if record is None:
                raise ValueError(f'ERROR Review not found: {review_id=}')
            return _sqlalchemy_recordDetachFromSession(record, dbSession)

    def review_complete(self, review_id: int, notes: str | None = None):
        with self.dbORM_RW.session() as dbSession:
            table_review = self.dbORM_RW.tables[self._review_table_name]
            table_review_columns = _table_columns(table_review)
            values = {
                'status': self.dbSchema.ReviewStatus.Completed.value,
                'completed': sqlalchemy.func.timezone('utc', sqlalchemy.func.now()),
            }
            if notes is not None:
                values['notes'] = notes
            record = dbSession.execute(
                update(table_review)
                .where(table_review_columns.id == int(review_id))
                .values(**values)
                .returning(table_review),
            ).scalar_one_or_none()
            if record is None:
                raise ValueError(f'ERROR Review not found: {review_id=}')
            dbSession.commit()
            return _sqlalchemy_recordDetachFromSession(record, dbSession)

    def finding_create(
            self,
            review_id: int,
            severity: str,
            title: str,
            description: str,
            creator_user_id: int,
    ):
        with self.dbORM_RW.session() as dbSession:
            table_finding = self.dbORM_RW.tables[self._finding_table_name]
            record = dbSession.execute(
                insert(table_finding).returning(table_finding),
                {
                    'review_id': int(review_id),
                    'severity': severity,
                    'title': title,
                    'description': description,
                    'creator_user_id': int(creator_user_id),
                },
            ).scalar_one()
            dbSession.commit()
            return _sqlalchemy_recordDetachFromSession(record, dbSession)

    def findings_readByReviewID(self, review_id: int):
        with self.dbORM_RO.session() as dbSession:
            table_finding = self.dbORM_RO.tables[self._finding_table_name]
            table_finding_columns = _table_columns(table_finding)
            records = dbSession.execute(
                select(table_finding)
                .where(table_finding_columns.review_id == int(review_id))
                .order_by(table_finding_columns.created.asc(), table_finding_columns.id.asc())
            ).scalars().all()
            return [_sqlalchemy_recordDetachFromSession(record, dbSession) for record in records]

    def finding_readByID(self, finding_id: int):
        with self.dbORM_RO.session() as dbSession:
            table_finding = self.dbORM_RO.tables[self._finding_table_name]
            table_finding_columns = _table_columns(table_finding)
            record = dbSession.execute(
                select(table_finding).where(table_finding_columns.id == int(finding_id))
            ).scalar_one_or_none()
            if record is None:
                raise ValueError(f'ERROR Finding not found: {finding_id=}')
            return _sqlalchemy_recordDetachFromSession(record, dbSession)

    def action_item_create(
            self,
            title: str,
            description: str,
            creator_user_id: int,
            finding_id: int | None = None,
            github_repo: str | None = None,
            github_issue_number: int | None = None,
            github_issue_url: str | None = None,
    ):
        with self.dbORM_RW.session() as dbSession:
            table_action_item = self.dbORM_RW.tables[self._action_item_table_name]
            record = dbSession.execute(
                insert(table_action_item).returning(table_action_item),
                {
                    'finding_id': None if finding_id in (None, '') else int(finding_id),
                    'title': title,
                    'description': description,
                    'github_repo': github_repo,
                    'github_issue_number': github_issue_number,
                    'github_issue_url': github_issue_url,
                    'status': self.dbSchema.ActionItemStatus.Open.value,
                    'creator_user_id': int(creator_user_id),
                },
            ).scalar_one()
            dbSession.commit()
            return _sqlalchemy_recordDetachFromSession(record, dbSession)

    def action_items_read(self, include_resolved: bool = True):
        with self.dbORM_RO.session() as dbSession:
            table_action_item = self.dbORM_RO.tables[self._action_item_table_name]
            table_action_item_columns = _table_columns(table_action_item)
            stmt = select(table_action_item)
            if not include_resolved:
                stmt = stmt.where(table_action_item_columns.status != self.dbSchema.ActionItemStatus.Resolved.value)
            records = dbSession.execute(
                stmt.order_by(table_action_item_columns.created.desc(), table_action_item_columns.id.desc())
            ).scalars().all()
            return [_sqlalchemy_recordDetachFromSession(record, dbSession) for record in records]

    def action_items_readByFindingID(self, finding_id: int):
        with self.dbORM_RO.session() as dbSession:
            table_action_item = self.dbORM_RO.tables[self._action_item_table_name]
            table_action_item_columns = _table_columns(table_action_item)
            records = dbSession.execute(
                select(table_action_item)
                .where(table_action_item_columns.finding_id == int(finding_id))
                .order_by(table_action_item_columns.created.asc(), table_action_item_columns.id.asc())
            ).scalars().all()
            return [_sqlalchemy_recordDetachFromSession(record, dbSession) for record in records]

    def action_item_readByID(self, action_item_id: int):
        with self.dbORM_RO.session() as dbSession:
            table_action_item = self.dbORM_RO.tables[self._action_item_table_name]
            table_action_item_columns = _table_columns(table_action_item)
            record = dbSession.execute(
                select(table_action_item).where(table_action_item_columns.id == int(action_item_id))
            ).scalar_one_or_none()
            if record is None:
                raise ValueError(f'ERROR Action item not found: {action_item_id=}')
            return _sqlalchemy_recordDetachFromSession(record, dbSession)

    def action_item_update_create(
            self,
            action_item_id: int,
            update_type: str,
            notes: str,
            creator_user_id: int,
    ):
        with self.dbORM_RW.session() as dbSession:
            table_action_item_update = self.dbORM_RW.tables[self._action_item_update_table_name]
            record = dbSession.execute(
                insert(table_action_item_update).returning(table_action_item_update),
                {
                    'action_item_id': int(action_item_id),
                    'update_type': update_type,
                    'notes': notes,
                    'creator_user_id': int(creator_user_id),
                },
            ).scalar_one()
            dbSession.commit()
            return _sqlalchemy_recordDetachFromSession(record, dbSession)

    def action_item_updates_readByActionItemID(self, action_item_id: int):
        with self.dbORM_RO.session() as dbSession:
            table_action_item_update = self.dbORM_RO.tables[self._action_item_update_table_name]
            table_action_item_update_columns = _table_columns(table_action_item_update)
            records = dbSession.execute(
                select(table_action_item_update)
                .where(table_action_item_update_columns.action_item_id == int(action_item_id))
                .order_by(table_action_item_update_columns.created.asc(), table_action_item_update_columns.id.asc())
            ).scalars().all()
            return [_sqlalchemy_recordDetachFromSession(record, dbSession) for record in records]

    def action_item_status_set(
            self,
            action_item_id: int,
            status: str,
            resolver_user_id: int | None = None,
    ):
        with self.dbORM_RW.session() as dbSession:
            table_action_item = self.dbORM_RW.tables[self._action_item_table_name]
            table_action_item_columns = _table_columns(table_action_item)
            values = {'status': status}
            if status == self.dbSchema.ActionItemStatus.Resolved.value:
                values['resolved'] = sqlalchemy.func.timezone('utc', sqlalchemy.func.now())
                values['resolver_user_id'] = None if resolver_user_id is None else int(resolver_user_id)
            else:
                values['resolved'] = None
                values['resolver_user_id'] = None
            record = dbSession.execute(
                update(table_action_item)
                .where(table_action_item_columns.id == int(action_item_id))
                .values(**values)
                .returning(table_action_item),
            ).scalar_one_or_none()
            if record is None:
                raise ValueError(f'ERROR Action item not found: {action_item_id=}')
            dbSession.commit()
            return _sqlalchemy_recordDetachFromSession(record, dbSession)

    def db_checkUpdateAvailable(self) -> bool:
        return not self.dbSchema.matches(self.dbORM_RO.engine)

    def db_update(self) -> None:
        try:
            self.dbSchema.update(self.dbORM_RW.engine)
        except sqlalchemy.exc.SQLAlchemyError as e:
            raise RuntimeError(
                'ERROR Failed to update the compliance database schema. '
                'The RW database user must have DDL privileges '
                '(`CREATE TABLE`, `ALTER TABLE`, `CREATE SCHEMA`).'
            ) from e
