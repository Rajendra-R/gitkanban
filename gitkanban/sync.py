import json
import urllib.parse

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import tornado.ioloop
import tornado.web

import requests
from deeputil import Dummy

from .models import Base
from .models import Organization, Repository, issue_user_assignee_rel_table, \
    issue_label_rel_table, Issue, IssueComment, User, Label


DUMMY_LOG = Dummy()


class ListenHandler(tornado.web.RequestHandler):
    def initialize(self, session, engine, event_filter_config, log=DUMMY_LOG):
        self.log = log
        self.session = session
        self.engine = engine
        self.event_filter_config = event_filter_config

    def post(self):
        # listens for post requests from Github webhooks, calls corresponding
        #   handler functions

        # FIXME: Add code to verify that the source of the event is indeed
        # Github, eg. x-hub-signature header

        # handle the event/action by passing to corresponding functions
        event = json.loads(self.request.body.decode('utf8'))
        action = event['action']
        event_name = self.request.headers['x-github-event']

        econf = self.event_filter_config
        if not (event_name in econf and action in econf[event_name]):
            # Terminate event processing as we don't want this event
            return

        try:
            handler_fn = getattr(self, 'handle_{}'.format(event_name))
            if not handler_fn:
                self.log.warning('missing_event_handler', _event=event_name, action=action)
                return

            handler_fn(event, action)

        except Exception:
            self.log.exception('event_handling_failed', _event=event_name, action=action)

    def add_get_user(self, user):
        # return User if exists, else create and return
        r = requests.get(user['url'])
        user = r.json()

        if self.session.query(User).filter_by(node_id=user['node_id']).first():
            return self.session.query(User).filter_by(node_id=user['node_id']).first()
        else:
            user_row = User(name=user['name'], login=user['login'],
                            company=user['company'], location=user['location'],
                            email=user['email'], avatar_url=user['avatar_url'],
                            node_id=user['node_id'], id=user['id'])
            self.session.add(user_row)
            self.session.commit()
            return user_row

    def add_get_label(self, label):
        # return Label if exists, else create and return

        if self.session.query(Label).filter_by(node_id=label['node_id']).first():
            return self.session.query(Label).filter_by(node_id=label['node_id']).first()
        else:
            label_row = Label(name=label['name'], description=None,
                              color=label['color'], node_id=label['node_id'],
                              id=label['id'])

            self.session.add(label_row)
            self.session.commit()
            return label_row

    def handle_organization(self, event, action):
        # organization: deleted, renamed

        # for query by node_id
        org_node = event['organization']['node_id']

        if action == 'deleted':
            self.session.query(Organization).filter_by(node_id=org_node).delete()
            self.session.commit()

        elif action == 'renamed':
            org = self.session.query(Organization).filter_by(node_id=org_node).first()
            org.name = event['organization']['name']
            self.session.commit()

        else:
            self.log.error('unknown_organization_action', _event=event, _action=action)

    def handle_repository(self, event, action):
        # repository: created, renamed, edited, deleted

        if action == 'created':
            # get repo's Organization
            r = requests.get(event['repository']['owner']['organizations_url'])
            org_node = r.json()['node_id']
            organization_row = self.session.query(Organization).filter_by(node_id=org_node).first()

            # create Repository row and add to session
            repository_row = Repository(name=event['repository']['name'], description=event['repository']['description'],
                                        owner_type=event['repository']['owner']['type'], owner_id=event['repository']['owner']['id'],
                                        organization=organization_row, node_id=event['repository']['node_id'],
                                        id=event['repository']['id'])
            self.session.add(repository_row)

            # create web hook for this repository
            create_webhook(repo)

            self.session.commit()

        elif action == 'renamed':
            repo_node = event['repository']['node_id']
            repo = self.session.query(Repository).filter_by(node_id=repo_node).first()
            repo.name = event['repository']['name']
            self.session.commit()

        elif action == 'edited':
            repo_id = event['repository']['id']
            repo = self.session.query(Repository).get(repo_id)
            # change and commit all attributes
            repo.description = event['repository']['description']
            repo.owner_id = event['repository']['owner']['id']
            repo.owner_type = event['repository']['owner']['type']
            self.session.commit()

        elif action == 'deleted':
            repo_node = event['repository']['node_id']
            self.session.query(Repository).filter_by(node_id=repo_node).delete()
            self.session.commit()

        else:
            self.log.error('unknown_repository_action', _event=event, _action=action)

    def handle_issues(self, event, action):
        # issues: opened, edited, deleted, transferred, closed, reopened, assigned, unassigned, labeled, unlabeled

        if action == 'opened':
            repo_node = event['repository']['node_id']
            repo_row = self.session.query(Repository).filter_by(node_id=repo_node).first()
            # create Issue row and add to session
            issue_row = Issue(number=event['issue']['number'], title=event['issue']['title'],
                              body=event['issue']['body'], state=event['issue']['state'],
                              closed_at=event['issue']['closed_at'], closed_by=None,
                              repository=repo_row, node_id=event['issue']['node_id'],
                              id=event['issue']['id'])
            self.session.add(issue_row)
            self.session.commit()

        elif action == 'edited':
            issue_id = event['issue']['id']
            issue = self.session.query(Issue).get(issue_id)
            # change and commit all attributes
            issue.title = event['issue']['title']
            self.session.commit()

        elif action == 'deleted' or action == 'transferred':
            # FIXME: remove deleted/transferred issue from all other table references
            issue_node = event['issue']['node_id']
            issue = self.session.query(Issue).filter_by(node_id=issue_node).delete()
            self.session.commit()

        elif action == 'closed':
            issue_id = event['issue']['id']
            issue = self.session.query(Issue).get(issue_id)
            # change and commit all attributes
            issue.state = event['issue']['state']
            issue.closed_at = event['issue']['closed_at']
            issue.closed_by = self.add_get_user(event['issue']['user'])
            self.session.commit()

        elif action == 'reopened':
            issue_id = event['issue']['id']
            issue = self.session.query(Issue).get(issue_id)
            # change and commit all attributes
            issue.state = event['issue']['state']
            self.session.commit()

        elif action == 'assigned':
            issue_node = event['issue']['node_id']
            issue = self.session.query(Issue).filter_by(node_id=issue_node).first()
            # change and commit all attributes
            for assignee in event['issue']['assignees']:
                issue.assignees.append(self.add_get_user(assignee))
            self.session.commit()

        elif action == 'unassigned':
            issue_node = event['issue']['node_id']
            issue = self.session.query(Issue).filter_by(node_id=issue_node).first()
            # change and commit all attributes
            issue.assignees.remove(self.add_get_user(event['assignee']))
            self.session.commit()

        elif action == 'labeled':
            issue_node = event['issue']['node_id']
            issue = self.session.query(Issue).filter_by(node_id=issue_node).first()
            # change and commit all attributes
            for label in event['issue']['labels']:
                issue.labels.append(self.add_get_label(label))
                self.session.commit()

        elif action == 'unlabeled':
            issue_node = event['issue']['node_id']
            issue = self.session.query(Issue).filter_by(node_id=issue_node).first()
            # change and commit all attributes
            issue.labels.remove(self.add_get_label(event['label']))
            self.session.commit()

        else:
            self.log.error('unknown_issue_action', _event=event, _action=action)

    def handle_issue_comment(self, event, action):
        # issue_comment: created, edited, deleted

        if action == 'created':
            issue_node = event['issue']['node_id']
            user_node = event['comment']['user']['node_id']
            issue_row = self.session.query(Issue).filter_by(node_id=issue_node).first()
            user_row = self.session.query(User).filter_by(node_id=user_node).first()

            # create Issue row and add to session
            issue_comment_row = IssueComment(issue=issue_row, user=user_row,
                                             body=event['comment']['body'],
                                             node_id=event['comment']['node_id'],
                                             id=event['comment']['id'])
            self.session.add(issue_comment_row)
            self.session.commit()

        elif action == 'edited':
            issue_comment_id = event['comment']['id']
            issue_comment = self.session.query(IssueComment).get(issue_comment_id)
            # change and commit all attributes
            issue_comment.body = event['comment']['body']
            self.session.commit()

        elif action == 'deleted':
            issue_comment_node = event['comment']['node_id']
            issue_comment = self.session.query(IssueComment).filter_by(
                node_id=issue_comment_node).delete()
            self.session.commit()

        else:
            self.log.error('unknown_issue_comment_action', _event=event, _action=action)

    def handle_label(self, event, action):
        # label: created, edited, deleted

        if action == 'created':
            # create Issue row and add to session
            label_row = Label(name=event['label']['name'], description=None,
                              color=event['label']['color'],
                              node_id=event['label']['node_id'], id=event['label']['id'])
            self.session.add(label_row)
            self.session.commit()

        elif action == 'edited':
            label_id = event['label']['id']
            label = self.session.query(Label).get(label_id)
            # change and commit all attributes
            label.name = event['label']['name']
            label.color = event['label']['color']
            self.session.commit()

        elif action == 'deleted':
            label_node = event['label']['node_id']
            # FIXME: before a label get deleted, must remove label from each issue it belongs to
            label = self.session.query(Label).filter_by(node_id=label_node).delete()
            self.session.commit()

        else:
            self.log.error('unknown_label_action', _event=event, _action=action)


class SyncCommand:
    PORT = 8888

    # important events and actions
    EVENT_FILTER_CONFIG = {
        "issue_comment": ["created", "edited", "deleted"],
        "issues": ["opened", "edited", "deleted", "transferred", "closed", "reopened", "assigned", "unassigned", "labeled", "unlabeled"],
        "label": ["created", "edited", "deleted"],
        # "organization": ["deleted", "renamed"], # FIXME: put back when there is Org level webhook
        "repository": ["created", "renamed", "edited", "deleted"]
    }

    def __init__(self, gitkanban):
        self.gitkanban = gitkanban
        self.config_json = None
        self.args = None
        self.log = None
        self.git = None
        self.session = None

    def register(self, subcommands):
        cmd = subcommands.add_parser('sync',
                                     help='Sync state from Github')
        cmd.add_argument('--db', required=True, type=str,
                         help='''SQLAlchemy Engine Connection String
            eg: mysql://scott:tiger@localhost/foo
            eg: sqlite:////tmp/test.db
            Refer: https://docs.sqlalchemy.org/en/13/core/engines.html
            ''')

        subcommands = cmd.add_subparsers()

        full_cmd = subcommands.add_parser('full',
                                          help='One-time full sync from Github via v3 API')
        full_cmd.add_argument('--webhook-loc', type=str, default=None,
                              help='''Location where this service is accessible for
                 Github to send Webhook events. eg: https://example.com/. Note
                 that a /listen will be appended to this URL before registration
                 with Github''')
        full_cmd.set_defaults(func=self.cmd_full_sync)

        listen_cmd = subcommands.add_parser('listen',
                                            help='Real-time incremental sync from Github via Webhooks')
        listen_cmd.add_argument('--port', type=int, default=self.PORT)
        listen_cmd.set_defaults(func=self.cmd_listen)

    def create_webhook(self, repo):
        # creates a webhook for the specified repository

        if not self.args.webhook_loc:
            return

        events = list(self.EVENT_FILTER_CONFIG.keys())

        webhook_loc = urllib.parse.urljoin(self.args.webhook_loc, 'listen')
        config = {
            "url": webhook_loc,
            "content_type": "json"
        }

        repo.create_hook(name='web', config=config, events=events, active=True)

    def populate_repos(self):
        # populate Repository table

        repos = self.get_all_repos()

        for repo in repos:
            # add/get repo's Organization
            organization_row = self.add_get_organization(repo.organization)

            # create Repository row and add to session
            repository_row = Repository(name=repo.name, description=repo.description,
                                        owner_type=repo.owner.type, owner_id=repo.owner.id,
                                        organization=organization_row, node_id=repo.raw_data['node_id'],
                                        id=repo.raw_data['id'])
            self.session.add(repository_row)

            # create web hook for this repository
            self.create_webhook(repo)

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
            closed_by = self.add_get_user(issue.closed_by)

            # create Issue row and add to session
            issue_row = Issue(number=issue.number, title=issue.title,
                              body=issue.body, state=issue.state,
                              closed_at=issue.closed_at, closed_by=closed_by,
                              repository=repo_row, node_id=issue.raw_data['node_id'],
                              id=issue.raw_data['id'])
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
                                             body=comment.body, node_id=comment.raw_data['node_id'],
                                             id=comment.raw_data['id'])
            self.session.add(issue_comment_row)

        # commit any changes in transaction buffer
        self.session.commit()

    # TODO: query by id instead of node_id?

    # add Label row to session by creating from repo
    def populate_labels(self, labels):
        """
        populate Labels table
        :param issue: Issue Github object
        :param issue_row: Issue table row from models
        """

        label_row = None

        for label in labels:
            # if there is no label, return None
            if label is None:
                return None

            # if existing Label
            if self.session.query(Label).filter_by(node_id=label.raw_data['node_id']).first():
                label_row = self.session.query(Label).filter_by(
                    node_id=label.raw_data['node_id']).first()
            else:  # create and add
                label_row = Label(name=label.name, description=label.description,
                                  color=label.color, node_id=label.raw_data['node_id'],
                                  id=label.raw_data['id'])
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

        # if there is no organization, return None
        if org is None:
            return None

        # if existing Organization
        if self.session.query(Organization).filter_by(node_id=org.raw_data['node_id']).first():
            org_row = self.session.query(Organization).filter_by(
                node_id=org.raw_data['node_id']).first()
        else:  # create and add
            org_row = Organization(login=org.login, name=org.name,
                                   description=org.description, email=org.email,
                                   node_id=org.raw_data['node_id'],
                                   id=org.raw_data['id'])
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

        # if there is no user, return None
        if user is None:
            return None

        # if existing User
        if self.session.query(User).filter_by(node_id=user.raw_data['node_id']).first():
            user_row = self.session.query(User).filter_by(node_id=user.raw_data['node_id']).first()
        else:  # create and add
            user_row = User(name=user.name, login=user.login,
                            company=user.company, location=user.location,
                            email=user.email, avatar_url=user.avatar_url,
                            node_id=user.raw_data['node_id'], id=user.raw_data['id'])
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

        # if there is no Label, return None
        if label is None:
            None

        # if existing Label
        if self.session.query(Label).filter_by(node_id=label.raw_data['node_id']).first():
            label_row = self.session.query(Label).filter_by(
                node_id=label.raw_data['node_id']).first()
        else:  # create and add
            label_row = Label(name=label.name, description=label.description,
                              color=label.color, node_id=label.raw_data['node_id'],
                              id=label.raw_data['id'])
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

    def cmd_full_sync(self):
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

    def cmd_listen(self):
        self.config_json = self.gitkanban.config_json
        self.args = self.gitkanban.args
        self.log = self.gitkanban.log

        # Connect to db
        engine = create_engine(self.args.db)

        # create session
        Session = sessionmaker()
        Session.configure(bind=engine)
        session = Session()

        app = tornado.web.Application([
            (r'/listen', ListenHandler, dict(
                log=self.log,
                session=session,
                engine=engine,
                event_filter_config=self.EVENT_FILTER_CONFIG,
            )),
        ])

        app.listen(self.args.port)
        tornado.ioloop.IOLoop.current().start()
