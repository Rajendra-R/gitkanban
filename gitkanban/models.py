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
    __tablename__ = 'organization'

    # attributes
    login = Column(Unicode(128))
    name = Column(Unicode(128))
    description = Column(Unicode)
    email = Column(Unicode(128))

    # bidirectional: one organization to many repositories
    repositories = relationship('Repository', back_populates='organization')

    def __repr__(self):
        return '<Organization(name={}, id={})>'.format(self.name, self.id)


class Repository(BaseMixin, Base):
    # https://api.github.com/repos/deep-compute/gitkanban
    __tablename__ = 'repository'
    __table_args__ = (
        UniqueConstraint('owner_type', 'owner_id', 'name'),
    )

    # attributes
    name = Column(Unicode(128))
    description = Column(Unicode)

    owner_type = Column(Unicode(128))
    owner_id = Column(Integer)
    owner = generic_relationship(owner_type, owner_id)

    # bidirectional: many repositories to one organization
    organization_id = Column(Integer, ForeignKey('organization.id'))
    organization = relationship('Organization', back_populates='repositories')

    # bidirectional: one repository to many issues
    issues = relationship('Issue', back_populates='repository')

    def __repr__(self):
        return '<Repository(name={}, id={})>'.format(self.name, self.id)


# bidirectional: many issues to many assignees (users)
issue_user_assignee_rel_table = Table('issue_user_assignee_rel', Base.metadata,
                                      Column('issue_id', Integer, ForeignKey('issue.id')),
                                      Column('user_id', Integer, ForeignKey('user.id')),
                                      UniqueConstraint('issue_id', 'user_id'),
                                      )
# bidirectional: many issues to many labels
issue_label_rel_table = Table('issue_label_rel', Base.metadata,
                              Column('issue_id', Integer, ForeignKey('issue.id')),
                              Column('label_id', Integer, ForeignKey('label.id')),
                              UniqueConstraint('issue_id', 'label_id'),
                              )


class Issue(BaseMixin, Base):
    __tablename__ = 'issue'
    __table_args__ = (
        UniqueConstraint('repository_id', 'number'),
    )

    # attributes
    number = Column(Integer)
    title = Column(Unicode(255))
    body = Column(Unicode)

    state = Column(String(32))  # FIXME: enum?
    closed_at = DateTime()

    # bidirectional: many issues to one repository
    repository_id = Column(Integer, ForeignKey('repository.id'))
    repository = relationship('Repository', back_populates='issues')

    # bidirectional: one issue to many issue_comments
    issue_comments = relationship('IssueComment', back_populates='issue')

    # bidirectional: many issues to many assignees (users)
    assignees = relationship('User', secondary=issue_user_assignee_rel_table,
                             back_populates='assigned_issues')

    # bidirectional: many issues to many labels
    labels = relationship('Label', secondary=issue_label_rel_table,
                          back_populates='issues')

    # bidirectional: many issues to one closed_by (user)
    closed_by_id = Column(Integer, ForeignKey('user.id'))
    closed_by = relationship('User')


class IssueComment(BaseMixin, Base):
    # https://api.github.com/repos/deep-compute/gitkanban/issues/comments/467112876
    __tablename__ = 'issuecomment'

    # attributes
    body = Column(Unicode)

    # bidirectional: many issue_comments to one issue
    issue_id = Column(Integer, ForeignKey('issue.id'))
    issue = relationship('Issue', back_populates='issue_comments')

    # bidirectional: many issue_comments to one user
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship('User')


class User(BaseMixin, Base):
    # https://api.github.com/users/prashanthellina
    __tablename__ = 'user'

    # attributes
    name = Column(Unicode(128))
    login = Column(Unicode(128))
    company = Column(Unicode(128))
    location = Column(Unicode(128))
    email = Column(Unicode(128))
    avatar_url = Column(Unicode(1024))

    # bidirectional: many users to many issues
    assigned_issues = relationship('Issue', secondary=issue_user_assignee_rel_table,
                                   back_populates='assignees')


class Label(BaseMixin, Base):
    __tablename__ = 'label'

    # attributes
    name = Column(Unicode(128))
    description = Column(Unicode)
    color = Column(String(32))

    # bidirectional: many labels to many issues
    issues = relationship('Issue', secondary=issue_label_rel_table,
                          back_populates='labels')
