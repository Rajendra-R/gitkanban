import os
import sqlite3

class ConstraintsStateDB(object):

    def __init__(self, db_path):

        if not os.path.exists(db_path):
            os.makedirs(db_path)

        self.db_table_name = 'constraints_state_info'

        self.conn = sqlite3.connect(os.path.join(db_path, 'constraints.db'))
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()

        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS {} (
                id text PRIMARY KEY NOT NULL UNIQUE,
                last_dt_executed text NOT NULL,
                co_continue numeric NOT NULL
            )'''.format(self.db_table_name)
        )

    def new_constraint(self, id, last_dt_executed, co_continue):
        self.cursor.execute('''
            INSERT INTO {} values (?, ?, ?)'''.format(self.db_table_name),
            (id, last_dt_executed, co_continue)
        )
        self.conn.commit()

    def get_constraint(self, id):
        self.cursor.execute("SELECT * from {} where id='{}'".format(self.db_table_name, id))
        records = [ i for i in self.cursor.fetchall() ]
        if records:
            row = records[0]
            return dict(zip(row.keys(), row))
