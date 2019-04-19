from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import Table, Column, Integer, String, Unicode,\
    DateTime, ForeignKey, UniqueConstraint
from sqlalchemy_utils import generic_relationship

Base = declarative_base()

class BaseMixin:

    id = Column(Integer, primary_key=True)
    node_id = Column(String(128))

    created_at = DateTime()
    updated_at = DateTime()

class Organization(BaseMixin, Base):
    # https://api.github.com/orgs/deep-compute
    __tablename__ = 'organizations'

    login = Column(Unicode(128))
    name = Column(Unicode(128))
    description = Column(Unicode)
    email = Column(Unicode(128))

    repositories = relationship('Repository', back_populates='organization')

    def __repr__(self):
        return '<Organization(name={}, id={})>'.format(self.name, self.id)

class Repository(BaseMixin, Base):
    # https://api.github.com/repos/deep-compute/gitkanban
    __tablename__ = 'repositories'
    __table_args__ = (
        UniqueConstraint('owner_type', 'owner_id', 'name'),
    )

    name = Column(Unicode(128))
    description = Column(Unicode)

    owner_type = Column(Unicode(128))
    owner_id = Column(Integer)
    owner = generic_relationship(owner_type, owner_id)

    organization_id = Column(Integer, ForeignKey('organizations.id'))
    organization = relationship('Organization', back_populates='repositories')

    def __repr__(self):
        return '<Repository(name={}, id={})>'.format(self.name, self.id)

issue_user_assignee_rel_table = Table('issue_user_assignee_rel', Base.metadata,
    Column('issue_id', Integer, ForeignKey('issues.id')),
    Column('user_id', Integer, ForeignKey('users.id')),
    UniqueConstraint('issue_id', 'user_id'),
)

issue_label_rel_table = Table('issue_label_rel', Base.metadata,
    Column('issue_id', Integer, ForeignKey('issues.id')),
    Column('label_id', Integer, ForeignKey('labels.id')),
    UniqueConstraint('issue_id', 'label_id'),
)

class Issue(BaseMixin, Base):
    __tablename__ = 'issues'
    __table_args__ = (
        UniqueConstraint('repository_id', 'number'),
    )

    repository_id = Column(Integer, ForeignKey('repositories.id'))
    repository = relationship('Repository', back_populates='issues')

    number = Column(Integer)
    title = Column(Unicode(255))
    body = Column(Unicode)

    state = Column(String(32)) # FIXME: enum?
    closed_at = DateTime()

    assignees = relationship('User', secondary=issue_user_assignee_rel_table,
        back_populates='assigned_issues')

    labels = relationship('Label', secondary=issue_label_rel_table,
        back_populates='issues')

    closed_by_id = Column(Integer, ForeignKey('users.id'))
    closed_by = relationship('User')

class IssueComment(BaseMixin, Base):
    # https://api.github.com/repos/deep-compute/gitkanban/issues/comments/467112876
    __tablename__ = 'issuecomments'

    issue_id = Column(Integer, ForeignKey('issues.id'))
    issue = relationship('Issue', back_populates='comments')

    user_id = Column(Integer, ForeignKey('users.id'))
    user = relationship('User')

    body = Column(Unicode)

class User(BaseMixin, Base):
    # https://api.github.com/users/prashanthellina
    __tablename__ = 'users'
    
    name = Column(Unicode(128))
    login = Column(Unicode(128))
    company = Column(Unicode(128))
    location = Column(Unicode(128))
    email = Column(Unicode(128))
    avatar_url = Column(Unicode(1024))

    assigned_issues = relationship('Issue', secondary=issue_user_assignee_rel_table,
        back_populates='assignees')

class Label(BaseMixin, Base):
    __tablename__ = 'labels'

    name = Column(Unicode(128))
    description = Column(Unicode)
    color = Column(String(32))
