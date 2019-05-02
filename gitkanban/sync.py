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

    # add Label row to session by creating from config file
    def populate_labels(self, config_file, session):

        labels = config_file['labels']
        label_names = list(labels.keys())

        for name in label_names:
            # get attributes by name
            color = labels[name]['color']
            description = labels[name]['description']

            label_row = Label(name=name, description=description, color=color)
            session.add(label_row)

    def run(self):
        self.args = self.gitkanban.args
        self.git = self.gitkanban.git
        self.config_json = self.gitkanban.config_json

        # Connect to db and drop existing tables
        # before creating required tables
        engine = create_engine(self.args.db)
        Base.metadata.drop_all(engine)
        Base.metadata.create_all(engine)

        # create session
        Session = sessionmaker()
        Session.configure(bind=engine)
        session = Session()

        # populate all labels from config file
        self.populate_labels(self.config_json, session)
        session.commit()
