import os
import sqlite3

class ConstraintsStateDB(object):

    def __init__(self, db_path):

        if not os.path.exists(db_path):
            os.makedirs(db_path)

        self.cfc_table_name = 'constraints_freq_check'

        self.conn = sqlite3.connect(os.path.join(db_path, 'constraints.db'))
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()

        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS {} (
                id text PRIMARY KEY NOT NULL UNIQUE,
                last_dt_executed text NOT NULL,
                co_continue numeric NOT NULL
            )'''.format(self.cfc_table_name)
        )

        self.failed_checks_table_name = 'failed_checks'

        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS {} (
                id text PRIMARY KEY NOT NULL UNIQUE,
                datetime text NOT NULL,
                cons_info text NOT NULL,
                issue_url text NOT NULL,
                alert_data text NOT NULL,
                alert_status text NOT NULL
            )'''.format(self.failed_checks_table_name)
        )

    def new_constraint(self, id, last_dt_executed, co_continue):
        self.cursor.execute('''
            INSERT OR REPLACE INTO {} values (?, ?, ?)'''.format(self.cfc_table_name),
            (id, last_dt_executed, co_continue)
        )
        self.conn.commit()

    def get_constraint(self, id):
        self.cursor.execute("SELECT * from {} where id='{}'".format(self.cfc_table_name, id))
        records = [ i for i in self.cursor.fetchall() ]
        if records:
            row = records[0]
            return dict(zip(row.keys(), row))

    def insert_failed_check_alert(self, id, datetime, cons_info, issue_url, alert_data, alert_status):
        self.cursor.execute('''
            INSERT OR REPLACE INTO {} values (?, ?, ?, ?, ?, ?)'''.format(self.failed_checks_table_name),
            (id, datetime, cons_info, issue_url, alert_data, alert_status)
        )
        self.conn.commit()
       
    def get_failed_check_alert(self, id=None, alert_status=None):
        if alert_status:
            self.cursor.execute("SELECT * from {} where alert_status='{}'".format(self.failed_checks_table_name, alert_status))
            records = [ i for i in self.cursor.fetchall() ]
            if records:
                return [dict(zip(i.keys(), i)) for i in records]
        elif id:
            self.cursor.execute("SELECT * from {} where id='{}'".format(self.failed_checks_table_name, id))
            records = [ i for i in self.cursor.fetchall() ]
            if records:
                row = records[0]
                return dict(zip(row.keys(), row))

    def delete_failed_check_alert(self, id):
        self.cursor.execute("DELETE FROM {} WHERE id='{}'".format(self.failed_checks_table_name, id))

