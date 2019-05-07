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
        self.session = None

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
    def populate_repos(self):
        # get list of all repos
        repos = self.get_all_repos()

        for repo in repos:
            # add and get repo's Organization
            organization_row = self.add_and_get_organization(repo)

            # create Repository row and add to session
            repository_row = Repository(name=repo.name, description=repo.description,
                                        owner_type=repo.owner.type, owner_id=repo.owner.id,
                                        organization=organization_row)
            self.session.add(repository_row)

            # add all Issue rows from repo
            self.populate_issues(repo, repository_row)

        # commit any changes in transaction buffer
        self.session.commit()

    def populate_issues(self, repo, repo_row):
        # get open issues from repo
        open_issues = repo.get_issues(state='open')

        for issue in open_issues:
            # get closed user and add to table
            closed_by = issue.closed_by
            self.add_and_get_user(closed_by)

            # create Issue row and add to session
            issue_row = Issue(number=issue.number, title=issue.title,
                              body=issue.body, state=issue.state,
                              closed_at=issue.closed_at, closed_by=issue.closed_by,
                              repository=repo_row)
            self.session.add(issue_row)

            # append issues to users and issues to labels
            self.append_issues_users(issue_row, issue.assignees)
            self.append_issues_labels(issue_row, issue.labels)

            # add all IssueComment rows from issue
            self.populate_issue_comments(issue, issue_row)

        # commit any changes in transaction buffer
        self.session.commit()

    def populate_issue_comments(self, issue, issue_row):
        # for each issue get issue comments
        for comment in issue.get_comments():
            # add and get IssueComment's User
            user_row = self.add_and_get_user(comment.user)

            # add issue_comment_row
            issue_comment_row = IssueComment(issue=issue_row, user=user_row,
                                             body=comment.body)
            self.session.add(issue_comment_row)

        # commit any changes in transaction buffer
        self.session.commit()

    # add Label row to session by creating from config file
    def populate_labels(self):
        # get list of label names
        labels = self.config_json['labels']
        label_names = list(labels.keys())

        for name in label_names:
            # get attributes by name
            color = labels[name]['color']
            description = labels[name]['description']

            label_row = Label(name=name, description=description, color=color)
            self.session.add(label_row)

        # commit any changes in transaction buffer
        self.session.commit()

    # add Organization row to session by creating or find existing
    #   :return: Organization row
    def add_and_get_organization(self, repo):

        # get organization of repo
        org_git = repo.organization
        org_row = None

        # if there is no organization, return empty Organization
        if not org_git:
            return Organization(login=None, name=None, description=None, email=None)

        # if existing Organization
        if self.session.query(Organization).filter_by(login=org_git.login).first():
            org_row = self.session.query(Organization).filter_by(login=org_git.login).first()
        else:  # if it doesn't exist, create & add it
            org_row = Organization(login=org_git.login, name=org_git.name,
                                   description=org_git.description, email=org_git.email)
            self.session.add(org_row)

        # commit any changes in transaction buffer
        self.session.commit()

        return org_row

    # add User row to session if it doesn't exist, return User
    def add_and_get_user(self, user):

        user_row = None

        # if there is no user, return empty User
        if not user:
            return User(name=None, login=None, company=None, location=None,
                        email=None, avatar_url=None)

        # if existing User
        if self.session.query(User).filter_by(login=user.login).first():
            user_row = self.session.query(User).filter_by(login=user.login).first()
        else:  # if User does not exist, create and add
            user_row = User(name=user.name, login=user.login,
                            company=user.company, location=user.location,
                            email=user.email, avatar_url=user.avatar_url)
            self.session.add(user_row)

        # commit any changes in transaction buffer
        self.session.commit()

        return user_row

    # add Label row to session if it doesn't exist, return Label
    def add_and_get_label(self, label):

        label_row = None

        # if there is no Label, return empty Label
        if not label:
            return Label(name=None, description=None, color=None)

        # if existing Label
        if self.session.query(Label).filter_by(name=label.name).first():
            label_row = self.session.query(Label).filter_by(name=label.name).first()
        else:  # if Label does not exist, create and add
            label_row = Label(name=label.name, description=label.description, color=label.color)
            self.session.add(label_row)

        # commit any changes in transaction buffer
        self.session.commit()

        return label_row

    # gets all repositories from config file
    #   :return: list of Repository objects
    def get_all_repos(self):

        # get repos from config file and git get_repo
        repo_groups = self.config_json['repo_groups']
        git = self.git

        # get all repos from each repo_group
        return [git.get_repo(str(*i.values())) for k, v in repo_groups.items() for i in v]

    def append_issues_users(self, issue_row, users):

        for user in users:
            # create User
            user_row = self.add_and_get_user(user)
            # append issue to user
            issue_row.assignees.append(user_row)

        # commit any changes in transaction buffer
        self.session.commit()

    def append_issues_labels(self, issue_row, labels):
        for label in labels:
            # create Label
            label_row = self.add_and_get_label(label)
            # append issue to label
            issue_row.labels.append(label_row)

        # commit any changes in transaction buffer
        self.session.commit()

    # populates each table manually to test relaionships, etc.
    def populate_all(self):

        # populate all labels from config file
        self.populate_labels()

        # populate Repository,
        self.populate_repos()

        # commit any changes in transaction buffer
        self.session.commit()

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
        self.session = Session()

        # populate all tables
        self.populate_all()
