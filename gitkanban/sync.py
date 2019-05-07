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

    def populate_repos(self):
        # populate Repository table

        repos = self.get_all_repos()

        for repo in repos:
            # add/get repo's Organization
            organization_row = self.add_get_organization(repo.organization)

            # create Repository row and add to session
            repository_row = Repository(name=repo.name, description=repo.description,
                                        owner_type=repo.owner.type, owner_id=repo.owner.id,
                                        organization=organization_row)
            self.session.add(repository_row)

            # add all Issue rows from repo
            self.populate_issues(repo, repository_row)

        # commit any changes in transaction buffer
        self.session.commit()

    def populate_issues(self, repo, repo_row, all_issues=False):
        """
        populate Issue table
        :param repo: Repository Github object
        :param repo_row: Repository table row from models
        :param all_issues: optional Boolean to get all issues or by default
                           only open issues
        """

        # get issue from repo
        if all_issues:
            issues = repo.get_issues()
        else:
            issues = repo.get_issues(state='open')

        for issue in issues:
            # get closed_by User and add to table
            closed_by = issue.closed_by
            self.add_get_user(closed_by)

            # create Issue row and add to session
            issue_row = Issue(number=issue.number, title=issue.title,
                              body=issue.body, state=issue.state,
                              closed_at=issue.closed_at, closed_by=issue.closed_by,
                              repository=repo_row)
            self.session.add(issue_row)

            # populate all Label rows from issue
            self.populate_labels(issue.labels)

            # append issues to users and issues to labels
            self.append_issue_users(issue_row, issue.assignees)
            self.append_issue_labels(issue_row, issue.labels)

            # add all IssueComment rows from issue
            self.populate_issue_comments(issue, issue_row)

        # commit any changes in transaction buffer
        self.session.commit()

    def populate_issue_comments(self, issue, issue_row):
        """
        populate IssueComment table
        :param issue: Issue Github object
        :param issue_row: Issue table row from models
        """

        for comment in issue.get_comments():
            # add and get IssueComment's User
            user_row = self.add_get_user(comment.user)

            # create IssueComment row and add to session
            issue_comment_row = IssueComment(issue=issue_row, user=user_row,
                                             body=comment.body)
            self.session.add(issue_comment_row)

        # commit any changes in transaction buffer
        self.session.commit()

    # add Label row to session by creating from repo
    def populate_labels(self, labels):
        """
        populate Labels table
        :param issue: Issue Github object
        :param issue_row: Issue table row from models
        """

        label_row = None

        for label in labels:
            # if there is no label, return empty Label
            if not label:
                return Organization(name=None, description=None, color=None)

            # if existing Label
            if self.session.query(Label).filter_by(name=label.name).first():
                label_row = self.session.query(Label).filter_by(name=label.name).first()
            else:  # create and add
                label_row = Label(name=label.name, description=label.description, color=label.color)
                self.session.add(label_row)

        # commit any changes in transaction buffer
        self.session.commit()

    def add_get_organization(self, org):
        """
        add single Organization row to the Organization table if it does not exist
        :param org: Organization Github object
        :return: Organization table object for a single row (org_row)
        """

        org_row = None

        # if there is no organization, return empty Organization
        if not org:
            return Organization(login=None, name=None, description=None, email=None)

        # if existing Organization
        if self.session.query(Organization).filter_by(login=org.login).first():
            org_row = self.session.query(Organization).filter_by(login=org.login).first()
        else:  # create and add
            org_row = Organization(login=org.login, name=org.name,
                                   description=org.description, email=org.email)
            self.session.add(org_row)

        # commit any changes in transaction buffer
        self.session.commit()

        return org_row

    def add_get_user(self, user):
        """
        add single User row to the User table if it does not exist
        :param user: User Github object
        :return: User table object for a single row (user_row)
        """

        user_row = None

        # if there is no user, return empty User
        if not user:
            return User(name=None, login=None, company=None, location=None,
                        email=None, avatar_url=None)

        # if existing User
        if self.session.query(User).filter_by(login=user.login).first():
            user_row = self.session.query(User).filter_by(login=user.login).first()
        else:  # create and add
            user_row = User(name=user.name, login=user.login,
                            company=user.company, location=user.location,
                            email=user.email, avatar_url=user.avatar_url)
            self.session.add(user_row)

        # commit any changes in transaction buffer
        self.session.commit()

        return user_row

    def add_get_label(self, label):
        """
        add single Label row to the Label table if it does not exist
        :param user: Label Github object
        :return: Label table object for a single row (label_row)
        """

        label_row = None

        # if there is no Label, return empty Label
        if not label:
            return Label(name=None, description=None, color=None)

        # if existing Label
        if self.session.query(Label).filter_by(name=label.name).first():
            label_row = self.session.query(Label).filter_by(name=label.name).first()
        else:  # create and add
            label_row = Label(name=label.name, description=label.description, color=label.color)
            self.session.add(label_row)

        # commit any changes in transaction buffer
        self.session.commit()

        return label_row

    def get_all_repos(self):
        # return list of Github Repository objects

        # get repos from repo groups
        repo_groups = self.config_json['repo_groups']
        git = self.git

        # use PyGithub to lookup each repository by name
        return [git.get_repo(str(*i.values())) for k, v in repo_groups.items() for i in v]

    def append_issue_users(self, issue_row, users):
        """
        append Issue row to each User row (for many to many relationship)
        :param issue_row: Issue Github object
        :param users: list of User table objects
        """

        for user in users:
            # add/get User and append Issue row to User row
            user_row = self.add_get_user(user)
            issue_row.assignees.append(user_row)

        # commit any changes in transaction buffer
        self.session.commit()

    def append_issue_labels(self, issue_row, labels):
        """
        append Issue row to each Label row (for many to many relationship)
        :param issue_row: Issue Github object
        :param labels: list of Label table objects
        """

        for label in labels:
            # add/get Label and append Issue row to Label row
            label_row = self.add_get_label(label)
            issue_row.labels.append(label_row)

        # commit any changes in transaction buffer
        self.session.commit()

    def populate_all(self):
        # populates each table starting with Repository table

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
