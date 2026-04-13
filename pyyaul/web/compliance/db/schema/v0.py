"""
Initial schema for the reusable compliance audit log module.
"""

from enum import Enum

from pyyaul.db.version import Version
from sqlalchemy import CheckConstraint, Column, Date, DateTime, ForeignKey, Index, Integer, String, Text, text
from sqlalchemy.engine.base import Engine
from sqlalchemy.schema import Table


class ComplianceSchemaV0_Base(Version):

    clsPrev = None
    schema_name: str | None = None

    class ReviewTopic(Enum):
        Security = 'security'
        Accessibility = 'accessibility'
        Legal = 'legal'
        Performance = 'performance'
        Privacy = 'privacy'
        Other = 'other'

    class ReviewStatus(Enum):
        InProgress = 'in_progress'
        Completed = 'completed'

    class FindingSeverity(Enum):
        Info = 'info'
        Warning = 'warning'
        Critical = 'critical'

    class ActionItemStatus(Enum):
        Open = 'open'
        InProgress = 'in_progress'
        Resolved = 'resolved'
        WontFix = 'wont_fix'

    class ActionItemUpdateType(Enum):
        Progress = 'progress'
        Resolved = 'resolved'
        Reopened = 'reopened'
        LinkedIssue = 'linked_issue'
        Comment = 'comment'

    def __init__(self, schema_name, *args, **kargs):
        self.schema_name = schema_name
        super().__init__(*args, **kargs)

    def _initialize(self, engine: Engine) -> Engine:
        if self.schema_name is not None:
            with engine.connect() as connection:
                with connection.begin() as transaction:
                    self.schema_create(connection, self.schema_name, True)
                    transaction.commit()
        return super()._initialize(engine)

    def _initMetaData(self, metadata):
        if self.schema_name is None:
            return

        review_topics = ', '.join(f"'{item.value}'" for item in self.ReviewTopic)
        review_statuses = ', '.join(f"'{item.value}'" for item in self.ReviewStatus)
        finding_severities = ', '.join(f"'{item.value}'" for item in self.FindingSeverity)
        action_statuses = ', '.join(f"'{item.value}'" for item in self.ActionItemStatus)
        update_types = ', '.join(f"'{item.value}'" for item in self.ActionItemUpdateType)

        table_compliance_review = Table(
            'table_compliance_review',
            metadata,
            Column('id', Integer, primary_key=True),
            Column('title', String(255), nullable=False),
            Column('review_date', Date, nullable=False),
            Column('topic', String(20), nullable=False),
            Column('scope', Text, nullable=False),
            Column('status', String(20), nullable=False, server_default=text("'in_progress'")),
            Column('created', DateTime(timezone=True), nullable=False, server_default=text("timezone('utc', now())")),
            Column('creator_user_id', Integer, nullable=False),
            Column('completed', DateTime(timezone=True), nullable=True),
            Column('notes', Text, nullable=True),
            CheckConstraint(f'topic IN ({review_topics})', name='check_table_compliance_review__topic'),
            CheckConstraint(f'status IN ({review_statuses})', name='check_table_compliance_review__status'),
            schema=self.schema_name,
        )
        Index(
            'index__table_compliance_review__status_review_date',
            table_compliance_review.c.status,
            table_compliance_review.c.review_date.desc(),
        )

        table_compliance_finding = Table(
            'table_compliance_finding',
            metadata,
            Column('id', Integer, primary_key=True),
            Column('review_id', Integer, ForeignKey(f'{self.schema_name}.table_compliance_review.id'), nullable=False),
            Column('severity', String(20), nullable=False),
            Column('title', String(255), nullable=False),
            Column('description', Text, nullable=False),
            Column('created', DateTime(timezone=True), nullable=False, server_default=text("timezone('utc', now())")),
            Column('creator_user_id', Integer, nullable=False),
            Column('resolved', DateTime(timezone=True), nullable=True),
            Column('resolver_user_id', Integer, nullable=True),
            CheckConstraint(f"severity IN ({finding_severities})", name='check_table_compliance_finding__severity'),
            schema=self.schema_name,
        )
        Index('index__table_compliance_finding__review_id', table_compliance_finding.c.review_id)

        table_action_item = Table(
            'table_action_item',
            metadata,
            Column('id', Integer, primary_key=True),
            Column('finding_id', Integer, ForeignKey(f'{self.schema_name}.table_compliance_finding.id'), nullable=True),
            Column('title', String(255), nullable=False),
            Column('description', Text, nullable=False),
            Column('github_repo', String(255), nullable=True),
            Column('github_issue_number', Integer, nullable=True),
            Column('github_issue_url', Text, nullable=True),
            Column('status', String(20), nullable=False, server_default=text("'open'")),
            Column('created', DateTime(timezone=True), nullable=False, server_default=text("timezone('utc', now())")),
            Column('creator_user_id', Integer, nullable=False),
            Column('resolved', DateTime(timezone=True), nullable=True),
            Column('resolver_user_id', Integer, nullable=True),
            CheckConstraint(f"status IN ({action_statuses})", name='check_table_action_item__status'),
            schema=self.schema_name,
        )
        Index('index__table_action_item__finding_id', table_action_item.c.finding_id)
        Index('index__table_action_item__status_created', table_action_item.c.status, table_action_item.c.created.desc())

        table_action_item_update = Table(
            'table_action_item_update',
            metadata,
            Column('id', Integer, primary_key=True),
            Column('action_item_id', Integer, ForeignKey(f'{self.schema_name}.table_action_item.id'), nullable=False),
            Column('update_type', String(20), nullable=False),
            Column('notes', Text, nullable=False),
            Column('created', DateTime(timezone=True), nullable=False, server_default=text("timezone('utc', now())")),
            Column('creator_user_id', Integer, nullable=False),
            CheckConstraint(f"update_type IN ({update_types})", name='check_table_action_item_update__update_type'),
            schema=self.schema_name,
        )
        Index('index__table_action_item_update__action_item_created', table_action_item_update.c.action_item_id, table_action_item_update.c.created.desc())
