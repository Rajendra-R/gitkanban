from sqlalchemy import create_engine

from .models import Base

class SyncCommand:
    def __init__(self, gitkanban):
        self.gitkanban = gitkanban
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

    def run(self):
        self.args = self.gitkanban.args
        self.git = self.gitkanban.git

        # Connect to db and drop existing tables
        # before creating required tables
        engine = create_engine(self.args.db)
        Base.metadata.drop_all(engine)
        Base.metadata.create_all(engine)
