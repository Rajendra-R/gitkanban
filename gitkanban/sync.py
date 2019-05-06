from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from .models import Base
from .models import Organization, Repository, issue_user_assignee_rel_table, \
    issue_label_rel_table, Issue, IssueComment, User, Label


class SyncCommand:
    def __init__(self, gitkanban):
        self.gitkanban = gitkanban
        self.config_json = None
        self.args = None
        self.git = None

    def register(self, subcommands):
        cmd = subcommands.add_parser('sync',
                                     help='Sync full state from Github')
        cmd.add_argument('--db', required=True, type=str,
                         help='''SQLAlchemy Engine Connection String
            eg: mysql://scott:tiger@localhost/foo
            eg: sqlite:////tmp/test.db
            Refer: https://docs.sqlalchemy.org/en/13/core/engines.html
            ''')
        cmd.set_defaults(func=self.run)

    # get all repos from config_json, get repos' organization
    def populate_repos(self, session):
        # get list of all repos
        repos = self.get_all_repos()

        for repo in repos:
            # add and get repo's Organization
            organization_row = self.add_and_get_organization(repo, session)

            # create Repository row and add to session
            repository_row = Repository(name=repo.name, description=repo.description,
                                        owner_type=repo.owner.type, owner_id=repo.owner.id,
                                        organization=organization_row)
            session.add(repository_row)

            # add all Issue rows from repo
            self.populate_issues(repo, repository_row, session)

    def populate_issues(self, repo, repo_row, session):
        # get open issues from repo
        open_issues = repo.get_issues(state='open')

        for issue in open_issues:

            # get closed user and add to table
            closed_by = issue.closed_by
            self.add_and_get_user(closed_by, session)

            # create Issue row and add to session
            issue_row = Issue(number=issue.number, title=issue.title,
                              body=issue.body, state=issue.state,
                              closed_at=issue.closed_at, closed_by=issue.closed_by,
                              repository=repo_row)
            session.add(issue_row)

            # add all IssueComment rows from issue
            self.populate_issue_comments(issue, issue_row, session)

    def populate_issue_comments(self, issue, issue_row, session):
        # for each issue get issue comments
        for comment in issue.get_comments():

            # add and get IssueComment's User
            user_row = self.add_and_get_user(comment.user, session)

            # add issue_comment_row
            issue_comment_row = IssueComment(issue=issue_row, user=user_row,
                                             body=comment.body)
            session.add(issue_comment_row)

        session.commit()

    # add Label row to session by creating from config file
    def populate_labels(self, session):
        # get list of label names
        labels = self.config_json['labels']
        label_names = list(labels.keys())

        for name in label_names:
            # get attributes by name
            color = labels[name]['color']
            description = labels[name]['description']

            label_row = Label(name=name, description=description, color=color)
            session.add(label_row)

        session.commit()

    # add Organization row to session by creating or find existing
    #   :return: Organization row
    def add_and_get_organization(self, repo, session):

        # get organization of repo
        org_git = repo.organization
        org_row = None

        # if there is no organization, return empty Organization
        if not org_git:
            return Organization(login=None, name=None, description=None, email=None)

        # if existing Organization
        if session.query(Organization).filter_by(login=org_git.login).first():
            org_row = session.query(Organization).filter_by(login=org_git.login).first()
        else:  # if it doesn't exist, create & add it
            org_row = Organization(login=org_git.login, name=org_git.name,
                                   description=org_git.description, email=org_git.email)
            session.add(org_row)

        return org_row

    # add User row to session if it doesn't exist
    def add_and_get_user(self, user, session):

        user_row = None

        # if there is no user, return empty User
        if not user:
            return User(name=None, login=None, company=None, location=None,
                        email=None, avatar_url=None)

        # if existing User
        if session.query(User).filter_by(login=user.login).first():
            user_row = session.query(User).filter_by(login=user.login).first()
        else:  # if User does not exist, create and add
            user_row = User(name=user.name, login=user.login,
                            company=user.company, location=user.location,
                            email=user.email, avatar_url=user.avatar_url)
            session.add(user_row)

        return user_row

    # gets all repositories from config file
    #   :return: list of Repository objects
    def get_all_repos(self):

        # get repos from config file and git get_repo
        repo_groups = self.config_json['repo_groups']
        git = self.git

        # get all repos from each repo_group
        return [git.get_repo(str(*i.values())) for k, v in repo_groups.items() for i in v]

    def append_issues_users(self):
        pass

    def append_issues_labels(self):
        pass

        # populates each table manually to test relaionships, etc.
    def populate_all(self, session):

        # populate Repository rows
        self.populate_repos(session)

        # populate all labels from config file
        self.populate_labels(session)

        # append issues to users and issues to labels
        self.append_issues_users()
        self.append_issues_labels()

    def run(self):
        self.config_json = self.gitkanban.config_json
        self.args = self.gitkanban.args
        self.git = self.gitkanban.git

        # Connect to db and drop existing tables
        # before creating required tables
        engine = create_engine(self.args.db)
        Base.metadata.drop_all(engine)
        Base.metadata.create_all(engine)

        # create session
        Session = sessionmaker()
        Session.configure(bind=engine)
        session = Session()

        # populate all tables
        self.populate_all(session)
