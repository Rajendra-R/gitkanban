import os
import sqlite3

TABLE_NAME = 'failed_checks'

class ConstraintsStateDB(object):

    def __init__(self, db_path):

        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()

        self.failed_checks_table_name = TABLE_NAME

        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS {} (
                constraint_name text NOT NULL,
                person text NOT NULL,
                issue_url text NOT NULL,
                datetime text NOT NULL,
                alert_issue_id numeric NOT NULL,
                PRIMARY KEY (issue_url, constraint_name)
            )'''.format(self.failed_checks_table_name))

        self.conn.commit()

    def insert_failed_check(self, constraint_name, person, issue_url, datetime, alert_issue_id):
        self.cursor.execute('''
            INSERT OR REPLACE INTO {} values (?, ?, ?, ?, ?)'''.format(self.failed_checks_table_name),
            (constraint_name, person, issue_url, datetime, alert_issue_id)
        )
        self.conn.commit()

    def get_failed_check(self, constraint_name=None, person=None, issue_url=None):
        if constraint_name and person and issue_url:
            self.cursor.execute("SELECT * from {} where constraint_name='{}' and issue_url='{}' and person='{}'".format(self.failed_checks_table_name, constraint_name, issue_url, person))
            records = [ i for i in self.cursor.fetchall() ]
            if records:
                row = records[0]
                return dict(zip(row.keys(), row))

        elif constraint_name and issue_url:
            self.cursor.execute("SELECT * from {} where constraint_name='{}' and issue_url='{}'".format(self.failed_checks_table_name, constraint_name, issue_url))
            records = [ i for i in self.cursor.fetchall() ]
            if records:
                row = records[0]
                return dict(zip(row.keys(), row))
        else:
            self.cursor.execute("SELECT * from {}".format(self.failed_checks_table_name))
            records = [ i for i in self.cursor.fetchall() ]
            if records:
                return [dict(zip(i.keys(), i)) for i in records]

    def delete_failed_check(self, constraint_name, issue_url):
        self.cursor.execute("DELETE FROM {} WHERE constraint_name='{}' and issue_url='{}'".format(self.failed_checks_table_name, constraint_name, issue_url))
        self.conn.commit()

