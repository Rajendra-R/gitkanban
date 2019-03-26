import sys
import json
import os
import requests
import datetime
import dateutil
import calendar
import hashlib
import copy
from pytz import timezone
from dateutil import parser
from dateutil.relativedelta import relativedelta

from pylru import lrucache
from github import Github, GithubException

from basescript import BaseScript
from .constarints_state import ConstraintsStateDB
from .exceptions import *

TIMESTAMP_NOW = lambda : datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
ISSUE_URL = 'https://api.github.com/repos/{}/issues'
LRU_CACHE_SIZE = 1000
PEOPLES_BLACKLIST = ["deepcompute-agent", "deep-compute-ops"]
ALERT_TITLE = "No comment for {} ({}#{}) {} [Gitkanban]"
ALERT_BODY = "No comment for **{}** ({}) {}."
DEFAULT_TIME_ELAPSED = "2h"

DEFAULT_ESCALATE_CONSTRAINT = {
    "time_elapsed": DEFAULT_TIME_ELAPSED,
    "priority": "high",
    "message": "Please resolve now",
    "escalate": True
}

OWNERSHIP_HIERARCHY = [
    "assignees",
    "repo-queue-label",
    "repo-queue",
    "repo-label",
    "repo",
    "repo-group-queue-label",
    "repo-group-queue",
    "repo-group-label",
    "repo-group",
    "system-owner"
]

class GitKanban(BaseScript):
    DESC = "A tool to enhance Github issue management with Kanban flow"

    def __init__(self, *args, **kwargs):
        super(GitKanban, self).__init__(*args, **kwargs)

        if self.args.github_access_token:
            self.git = Github(self.args.github_access_token)
        else:
            self.git = Github(self.args.username, self.args.password)

        #TODO: Before validate the config file, fill with default values, with all keys
        #TODO: validate the config file
        # read conf file
        if self.args.config_file:
            with open(self.args.config_file) as f:
                self.config_json = json.loads(f.read())

        self.lru = lrucache(LRU_CACHE_SIZE)

    def define_subcommands(self, subcommands):
        '''
        Specify all the sub-commands of this tool
        '''
        super(GitKanban, self).define_subcommands(subcommands)

        # ensure_labels arguments
        ensure_labels_cmd = subcommands.add_parser('ensure-labels',
            help='create or modify the labels'
        )
        ensure_labels_cmd.set_defaults(func=self.ensure_labels)

        # check_constraints arguments
        check_constraints_cmd = subcommands.add_parser('check-constraints',
            help="check the label constraints"
        )
        check_constraints_cmd.set_defaults(func=self.check_constraints)
        check_constraints_cmd.add_argument('-a', '--alert-repo', type=str,
            help="github alert repository name ex: 'alerts'",
        )
        check_constraints_cmd.add_argument("--db", required=True, type=self.check_db_type,
            help="check the db file name ex: state.db or /tmp/state.db",
        )

        # ensure_repo_group_labels arguments
        ensure_repo_group_labels = subcommands.add_parser('ensure-repo-group-labels',
            help="create the repo_group labels to the repo in that group"
        )
        ensure_repo_group_labels.set_defaults(func=self.ensure_repo_group_labels)

    def send_alert_to_github(self, alert_repo, alert_msg, record=None):
        # send alert to github
        try:
            if record:
                get_alert_issue = alert_repo.get_issue(number=record['alert_issue_id'])
                if get_alert_issue.state == "closed":
                    get_alert_issue.edit(state="open")
                    self.log.info("re_open_manually_closed_alert", alert_url=get_alert_issue.url)
                get_alert_issue.add_to_assignees(alert_msg['person_name'])
                existed_names = record['person'].split(',')
                if alert_msg['person_name'] in existed_names:
                    return
                existed_names.append(alert_msg['person_name'])
                p_names = ','.join(existed_names)
                # insert record to failed check table
                self.constraints_db.insert_failed_check(
                    record['constraint_name'],
                    p_names,
                    record['issue_url'],
                    TIMESTAMP_NOW(),
                    record['alert_issue_id'],
                    record['escalation_hierarchy']
                )
                self.log.info("add_assignee_to_existing_alert", **alert_msg)
            else:
                labels=[
                    '{}-priority'.format(alert_msg['priority']),
                    '{}-repo'.format(alert_msg['repo_name']),
                    '{}-queue'.format(alert_msg['queue_name']),
                    '{}-constraint'.format(alert_msg['constraint_name'])
                ]
                if alert_msg['repo_group_name']:
                    labels.append('{}-repo-group'.format(alert_msg['repo_group_name']))

                tail_desc = None
                desc_split = alert_msg['constraint_desc'].split('issue')
                if len(desc_split) == 2:
                    tail_desc = desc_split[-1].strip()

                #TODO: check it is making multiple github api calls?
                alert_issue = alert_repo.create_issue(
                    title=ALERT_TITLE.format(alert_msg['issue_title'], alert_msg['repo_name'], alert_msg['issue_no'], tail_desc),
                    body=ALERT_BODY.format(alert_msg['issue_title'], alert_msg['issue_html_url'], tail_desc),
                    assignees=[alert_msg['person_name']],
                    labels=labels
                )
                # insert record to failed check table
                self.constraints_db.insert_failed_check(
                    alert_msg['constraint_name'],
                    alert_msg['person_name'],
                    alert_msg['issue_url'],
                    TIMESTAMP_NOW(),
                    alert_issue.number,
                    alert_msg['ownership_hierarchy']
                )
                self.log.info('successfully_inserted_alert_to_github')
        except GithubException as e:
            if e.data['message'] == "Validation Failed":
                self.log.exception('got_error_while_inserting_alert', issue_url=alert_msg['issue_html_url'], error=e.data['errors'])
            else:
                self.log.exception('github_api_call_failed_while_inserting_alert', error=e)

    def close_alert_to_github(self, alert_repo, alert_msg, record):
        try:
            get_alert_issue = alert_repo.get_issue(number=record['alert_issue_id'])
            if get_alert_issue.state == "closed":
                self.log.info("alert_is_already_closed", alert_url=get_alert_issue.url)
            else:
                get_alert_issue.create_comment(body="**Gitkanban:** Auto-Resolved")
                get_alert_issue.edit(state='closed')
                self.log.info('successfully_closed_alert_to_github', **alert_msg)

            self.constraints_db.delete_failed_check(
                alert_msg['constraint_name'],
                alert_msg['issue_url']
            )
            alert_msg['alert_status'] = 'resolved'
            self.log.info('successfully_deleted_record_in_db', **alert_msg)
        except GithubException as e:
            if e.data['message'] == "Validation Failed":
                self.log.exception('got_error_while_closing_alert', error=e.data['errors'])
            else:
                self.log.exception('github_api_call_failed_while_closing_alert', error=e)

    def send_escalation_to_alert_issue(self, alert_repo, follow_up, record, peoples_list=None, own_hi=None):
        get_alert_issue = alert_repo.get_issue(number=record['alert_issue_id'])
        if get_alert_issue.state == "closed":
            get_alert_issue.edit(state="open")
            self.log.info("re_open_manually_closed_alert", alert_url=get_alert_issue.url)

        # add new escalation priority label
        new_label = "{}-priority".format(follow_up['priority'])
        existing_labels = [l.name for l in get_alert_issue.get_labels()]
        if not new_label in existing_labels:
            # delete existing priority label
            for i in existing_labels:
                if 'priority' in i:
                    get_alert_issue.remove_from_labels(i)

            get_alert_issue.add_to_labels(new_label)

        if not peoples_list:
            # send alert msg to assignees
            msg = "**Gitkanban:** {}".format(follow_up['message'])
            get_alert_issue.create_comment(body=msg)
            self.log.info('send_alert_to_assignees')
            # insert record to failed check table
            alerts = record['escalation_hierarchy'].split(',')
            alerts.append(follow_up['ownership'])
            t_alerts = ','.join(alerts)
            self.constraints_db.insert_failed_check(
                record['constraint_name'],
                record['person'],
                record['issue_url'],
                TIMESTAMP_NOW(),
                record['alert_issue_id'],
                t_alerts
            )
            return

        if own_hi == record['escalation_hierarchy']:
            return

        # send escalation msg to alert issue
        msg = "**Gitkanban:** Escalates to **@{}** {}".format(', @'.join(peoples_list), follow_up['message'])
        get_alert_issue.create_comment(body=msg)
        # add escalate persons to assignees
        existed_names = record['person'].split(',')
        for p in peoples_list:
            if p in existed_names:
                continue
            get_alert_issue.add_to_assignees(p)
            existed_names.append(p)

        p_names = ','.join(existed_names)

        # insert record to failed check table
        self.constraints_db.insert_failed_check(
            record['constraint_name'],
            p_names,
            record['issue_url'],
            TIMESTAMP_NOW(),
            record['alert_issue_id'],
            own_hi
        )
        self.log.info('send_escalation_msg')

    def check_file_type(self, path):
        if not path.endswith('.json'):
            raise InvalidFileTypeException("prefered .json extension")
        return path

    def check_db_type(self, path):
        if not path.endswith('.db'):
            raise InvalidDBTypeException("prefered .db extension")
        return path

    def get_repo_list(self):
        config_repo_groups = self.config_json.get('repo_groups', {})
        final_repo_list = []
        try:
            for k, v in config_repo_groups.items():
                if isinstance(v, list):
                    for r in v:
                        r['repo_group'] = k
                        repo_name = r.get('repo', '')
                        if '/' in repo_name:
                            r['repo'] = self.git.get_repo(repo_name)
                        else:
                            r['repo'] = self.git.get_user().get_repo(repo_name)

                        final_repo_list.append(r)
        except GithubException as e:
            if e.data['message'] == "Server Error":
                raise GithubAPIException("Got Github Server Error Exception")
            elif e.data['message'] == "Not Found":
                self.log.exception('invalid_repository_name', repo_name=rn)
            elif 'API rate limit exceeded for user ID' in e.data['message']:
                self.log.exception('api_rate_limit_exceeded', repo_name=rn)
            elif e.data['message'] == "Validation Failed":
                self.log.exception('got_validation_failed', error=e.data['errors'])
            sys.exit(1)

        return final_repo_list

    def ensure_labels(self):
        final_repo_list = self.get_repo_list()

        # create/update/delete label inside repo
        for rep in final_repo_list:
            rep = rep['repo']
            label_exist_count = 0
            label_edited_count = 0
            label_new_count = 0
            existing_labels = []
            for i in rep.get_labels():
                existing_labels.append(i.name)

            labels = self.config_json.get('labels', {})
            for k, v in labels.items():
                label_name = k
                color = v['color']
                desc = v['description']
                akas = v['akas']
                edit_flag = False
                if akas:
                    for aka in akas:
                        if aka in existing_labels:
                            edit_flag = True
                            label_edited_count += 1
                            try:
                                rep.get_label(aka).edit(k, color)
                            except GithubException as e:
                                if e.data['message'] == "Server Error":
                                    raise GithubAPIException("Got Github Server Error Exception")
                                aka_label = rep.get_label(aka)
                                aka_label_issues = rep.get_issues(labels=[aka_label])
                                #TODO: collect metrics
                                for ali in aka_label_issues:
                                    ali.add_to_labels(k)
                                    ali.remove_from_labels(aka)
                                rep.get_label(aka).delete()

                if not edit_flag:
                    try:
                        if label_name in existing_labels:
                            label_exist_count += 1
                            continue
                        if desc:
                            rep.create_label(label_name, color, desc)
                        else:
                            rep.create_label(label_name, color)
                        label_new_count += 1
                    except GithubException as e:
                        if e.data['message'] == "Server Error":
                            raise GithubAPIException("Got Github Server Error Exception")
                        elif e.data['message'] == "Validation Failed":
                            self.log.exception('got_validation_failed', error=e.data['errors'])
                        label_exist_count += 1

            self.log.info("successfully_created_labels", type="metric",
                repository=rep.name,
                label_created_new=label_new_count,
                label_already_exist=label_exist_count,
                label_edited=label_edited_count,
            )

    def get_people(self, repo_name, issue, ownership_index, queues_list, repo_groups, ownership_list, ownership):
        # prepare label separation for each issue
        # if issue has "next", "bug-type" labels
        # if that repo is present in our repo_group
        # -> ["queue:next", "label:bug-type", "repo:gitchecking/third", "repo_group:group1"]
        issue_labels = [l['name'] for l in issue['labels']]
        issue_assignees = [a['login'] for a in issue['assignees']]
        check_issue_index = []
        for l in issue_labels:
            if l in queues_list:
                key = "queue:{}".format(l)
            else:
                key = "label:{}".format(l)
            check_issue_index.append(key)

        check_issue_index.append("repo:{}".format(repo_name))

        for rn, rv in repo_groups.items():
            if repo_name in [r['repo'].full_name for r in rv]:
                check_issue_index.append('repo_group:{}'.format(rn))

        # get all the ownership indexes from the config file of a issue
        issue_ownership_index = []
        for c in check_issue_index:
            issue_ownership_index.append(ownership_index.get(c, None))

        issue_ownership_index = list(filter(None, issue_ownership_index)) # [{0,1,2}, {1,2}, {2,3}]

        issue_ownership_intersection = set()
        if issue_ownership_index:
            issue_ownership_intersection = set.intersection(*issue_ownership_index) # {2}

        # get ownership dic of a index from the config ownership [{}, {}]
        final_ownership_list = []
        for p in issue_ownership_intersection:
            final_ownership_list.append(ownership_list[p])

        # get the selected people from the config ownership based on issue
        ownership_people = {}
        for op in final_ownership_list:
            #TODO: if we miss order the keys in the config file
            key = '-'.join([k.replace('_', '-') for k in op.keys() if not k == 'people'])
            ownership_people[key] = op['people']

        # add assignees of a issue
        if issue_assignees:
            ownership_people['assignees'] = issue_assignees

        # add system_owner
        ownership_people['system_owner'] = self.system_owners

        # get the people based on our ownership hierarchy
        people = ()
        if ownership in ownership_people.keys():
            people = (ownership, ownership_people[ownership])

        if not people:
            people = (None, [])

        return people

    def check_last_constraint_executed(self, co, last_executed_record):
        past = last_executed_record['datetime']
        current = TIMESTAMP_NOW()

        start = datetime.datetime.strptime(past, '%Y-%m-%dT%H:%M:%SZ')
        end = datetime.datetime.strptime(current, '%Y-%m-%dT%H:%M:%SZ')

        diff = relativedelta(end, start)

        co_freq = co['frequency']
        if co_freq == "monthly":
            if diff.months >= 1:
                return True
        elif co_freq == "weekly":
            if diff.weeks >= 1:
                return True
        elif co_freq == "hourly":
            if diff.hours >= 1:
                return True

        return False

    def is_already_requested(self, url, params):
        # check recently do we already req this url
        _id = hashlib.md5("{}:{}".format(url, params).encode('utf8')).hexdigest()
        is_seen = _id in self.lru
        return (is_seen, _id)

    def make_request(self, url, params=None):
        params = params or {}
        params['access_token'] = self.args.github_access_token
        already_requested, _id = self.is_already_requested(url, params)
        # check response form the cache.
        if already_requested:
            resp_obj, data = self.lru[_id]
            self.log.info('get_response_from_cache', url=url, params=params)
            return (resp_obj, data)

        try:
            resp_obj = requests.get(url, params=params)
            data = resp_obj.json()
            self.request_count += 1
            self.log.info('successfully_reqested_a_url', url=url, params=params)
        except Exception as e:
            self.log.exception('not_able_to_request', url=url, error=e)

        if isinstance(data, dict):
            if data.get('message', '') == 'Not Found':
                self.log.exception("No data found exception", data=data, url=url)
                return
            elif data.get('message', '') == "Server Error":
                self.log.exception("Got Github Server Error Exception", data=data, url=url)
                return

            data = [data]

        self.lru[_id] = (resp_obj, data)
        return (resp_obj, data)

    def check_person_is_in_work_hours(self, people):
        p_name = people['name']
        p_location = people['location']
        pwh_start = people['work_hours']['start']
        pwh_start_h, pwh_start_m = pwh_start.split(':')
        pwh_end = people['work_hours']['end']
        pwh_end_h, pwh_end_m = pwh_end.split(':')
        p_timezone = self.config_json.get('locations', {}).get(p_location, {}).get('timezone', '')

        # convert person timezone current time to UTC timezone
        p_current_time = datetime.datetime.now(timezone(p_timezone))
        p_current_time_utc = datetime.datetime.now(timezone(p_timezone)).astimezone(timezone('UTC')).time()


        # person UTC working time start
        self.pwh_start_utc = p_current_time.replace(hour=int(pwh_start_h), minute=int(pwh_start_m)).astimezone(timezone('UTC')).strftime('%Y-%m-%dT%H:%M:%SZ')
        pwh_start_utc_hours = parser.parse(self.pwh_start_utc).hour
        pwh_start_utc_minute = parser.parse(self.pwh_start_utc).minute

        # person UTC working time end
        self.pwh_end_utc = p_current_time.replace(hour=int(pwh_end_h), minute=int(pwh_end_m)).astimezone(timezone('UTC')).strftime('%Y-%m-%dT%H:%M:%SZ')
        pwh_end_utc_hours = parser.parse(self.pwh_end_utc).hour
        pwh_end_utc_minute = parser.parse(self.pwh_end_utc).minute

        start = datetime.time(pwh_start_utc_hours, pwh_start_utc_minute)
        end = datetime.time(pwh_end_utc_hours, pwh_end_utc_minute)
        return (start <= p_current_time_utc <= end)

    def get_issue_created_datetime(self, issue_created_at, people):
        # person config info
        p_name = people['name']
        p_location = people['location']
        pwh_start = people['work_hours']['start']
        pwh_start_h, pwh_start_m = pwh_start.split(':')
        pwh_end = people['work_hours']['end']
        pwh_end_h, pwh_end_m = pwh_end.split(':')
        p_timezone = self.config_json.get('locations', {}).get(p_location, {}).get('timezone', '')

        # convert person timezone current time to UTC timezone
        p_current_time = datetime.datetime.now(timezone(p_timezone))
        self.p_current_time_utc = datetime.datetime.now(timezone(p_timezone)).astimezone(timezone('UTC')).strftime('%Y-%m-%dT%H:%M:%SZ')

        # person UTC working time start
        self.pwh_start_utc = p_current_time.replace(hour=int(pwh_start_h), minute=int(pwh_start_m)).astimezone(timezone('UTC')).strftime('%Y-%m-%dT%H:%M:%SZ')
        pwh_start_utc_hours = parser.parse(self.pwh_start_utc).hour
        pwh_start_utc_minute = parser.parse(self.pwh_start_utc).minute

        # person UTC working time end
        self.pwh_end_utc = p_current_time.replace(hour=int(pwh_end_h), minute=int(pwh_end_m)).astimezone(timezone('UTC')).strftime('%Y-%m-%dT%H:%M:%SZ')
        pwh_end_utc_hours = parser.parse(self.pwh_end_utc).hour
        pwh_end_utc_minute = parser.parse(self.pwh_end_utc).minute

        # issue updated at UTC time
        isu_hour = parser.parse(issue_created_at).hour
        isu_minute = parser.parse(issue_created_at).minute

        # check the issue date it belongs to which region of the day.
        if isu_hour >= pwh_start_utc_hours:
            if isu_hour <= pwh_end_utc_hours:
                # if issue date is in working hours
                return issue_created_at
            else:
                # if issue date is after the working hours ends
                issue_created_at_obj = parser.parse(issue_created_at)
                issue_created_at_obj += datetime.timedelta(days=1)
                # Should not consider weekends.
                if calendar.day_name[issue_created_at_obj.date().weekday()] == "Saturday":
                    issue_created_at_obj += datetime.timedelta(days=1)
                    issue_created_at_obj += datetime.timedelta(days=1)
                elif calendar.day_name[issue_created_at_obj.date().weekday()] == "Sunday":
                    issue_created_at_obj += datetime.timedelta(days=1)
                issue_created_at = issue_created_at_obj.replace(hour=pwh_start_utc_hours, minute=pwh_start_utc_minute).strftime('%Y-%m-%dT%H:%M:%SZ')
                return issue_created_at
        else:
            # if issue date is before the working hours start
            issue_created_at = parser.parse(issue_created_at).replace(hour=pwh_start_utc_hours, minute=pwh_start_utc_minute).strftime('%Y-%m-%dT%H:%M:%SZ')
            return issue_created_at


    def calculate_time_constraint(self, time_constraint, issue_created_at, p_current_time_utc):
        if 'd' in time_constraint:
            days, _ = time_constraint.split('d')
            c_hours = int(days) * 24
        elif 'h' in time_constraint:
            c_hours, _ = time_constraint.split('h')
        else:
            self.log.error('invalid_time_constraint', constraint_time=time_constraint)
            return False

        diff_time = relativedelta(parser.parse(p_current_time_utc), parser.parse(issue_created_at))
        months = diff_time.months
        days = diff_time.days
        hours = diff_time.hours

        #TODO: check year, months having 31, holidays, leapyear,..
        total_hours = int(((months * 30) * 24) + (days * 24) + hours)
        return (total_hours >= int(c_hours))

    def check_constraint(self, constraint, issue, people):
        # issue already closed but when issue come from our failed table.
        if issue['state'] == "closed":
            return False
        # req a issue comments url to get the last comment info
        comments_url = issue['comments_url']
        params = {"per_page": 100}
        try:
            res_obj, data = self.make_request(comments_url, params)
            last_page = res_obj.links.get('last', {}).get('url', '')
            if last_page:
                com_res_obj, data = self.make_request(last_page, params)
        except TypeError:
            return False

        if data:
            issue_data = data[-1]
        else:
            issue_data = issue

        issue_created_at = issue_data['created_at']
        issue_updated_at = issue_data['updated_at']

        time_constraint = constraint.get('time_since_creation', '') or constraint.get('time_since_activity', '')

        # check the person is in working hours
        # based on our custom timezone logic of a person change the issue created time
        issue_created_at = self.get_issue_created_datetime(issue_created_at, people)
        return self.calculate_time_constraint(time_constraint, issue_created_at, self.p_current_time_utc)

    def check_constraints(self):
        # prepare owndership index from the given config file
        # d = [{'a': 'a1', 'b': 'b1', 'c': 'c1'}, {'a': 'a1', 'd': 'd1'}, {'b': 'b1'}, {'e': 'e1'}]
        # {'a:a1': {0, 1}, 'b:b1': {0, 2}, 'c:c1': {0}, 'd:d1': {1}, 'e:e1': {3}}
        self.constraints_db = ConstraintsStateDB(self.args.db)
        self.request_count = 0
        ownership_list = self.config_json.get('ownership', [])
        self.system_owners = next(o['system_owner'] for o in ownership_list if o.get('system_owner', []))
        ownership_index = {}
        for index, o in enumerate(ownership_list):
            for k, v in o.items():
                if k == "people":
                    continue
                key = "{}:{}".format(k,v)
                if key in ownership_index.keys():
                    ownership_index[key].add(index)
                else:
                    value = set()
                    value.add(index)
                    ownership_index[key] = value

        constraints = self.config_json.get('constraints', [])
        co_info = {}
        for i in constraints:
            if isinstance(i, list):
                for ci in i:
                    co_info[ci['name']] = ci
            elif isinstance(i, dict):
                co_info[i['name']] = i

        queues = self.config_json.get('queues', {})
        queues_list = queues.values()
        peoples = self.config_json.get('people', {})
        dc_peoples_list = peoples.keys()
        repo_groups = self.config_json.get('repo_groups', {})
        # get the alert repo
        alert_repo = self.git.get_repo(self.args.alert_repo)
        # get all the repo's from the user specs
        final_repo_list = self.get_repo_list()

        # sub function
        def __check_constraints(self, co=None, check_alert_issues=False, record=None):
            if check_alert_issues:
                co = co_info[record['constraint_name']]
            co_queue_name = co.get('queue', '')
            actual_q_name = queues[co_queue_name]
            # add params from config before going to request
            if not actual_q_name:
                params = {} # for inbox case
            else:
                if repo.get('label', ''):
                    label_names = "{},{}".format(actual_q_name, repo['label'])
                else:
                    label_names = actual_q_name
                params = {"labels": label_names}

            if repo.get('assignee', ''):
                params['assignee'] = repo['assignee']

            params['per_page'] = 100

            if check_alert_issues:
                req_url = record['issue_url']
            else:
                # req a repo url to get the issues, default will get only open issues
                req_url = ISSUE_URL.format(repo_name)

            # req a issue url with pagination
            while True:
                try:
                    resp_obj, issues_list = self.make_request(req_url, params=params)
                except TypeError:
                    break

                next_page = resp_obj.links.get('next', {})

                # get issues for inbox constraints
                if co_queue_name == "inbox":
                    issues_list = [i for i in issues_list if not any (ln in queues_list for ln in [l['name'] for l in i['labels'] if l['name']])]

                for issue in issues_list:
                    issue_url = issue['url']

                    # skip the issues which are passed in the before constraint of first run
                    if issue_url in tmp_check_list.keys():
                        if not tmp_check_list[issue_url]:
                            continue

                    if issue_url in tmp_nxt_check_list:
                        continue

                    # if issue moved from one queue to other after alert
                    # make a auto-resolve for the alerted issue
                    if check_alert_issues:
                        if actual_q_name not in [l['name'] for l in issue['labels']]:
                            alert_msg = {"constraint_name": co['name'], "issue_url": issue_url}
                            self.close_alert_to_github(alert_repo, alert_msg, record)
                            continue

                    # phase-1 Regular constraint ran
                    if not check_alert_issues:
                        # check last executed from sqlite
                        co_name = co['name']
                        co_feruency = co['frequency']
                        co_continue = co['continue']
                        check_co_id = "{}:{}".format(co_name, issue_url)
                        last_executed_record = self.constraints_db.get_failed_check(constraint_name=co_name,
                            issue_url=issue_url
                        )
                        if last_executed_record:
                            if not self.check_last_constraint_executed(co, last_executed_record):
                                if not co_continue:
                                    tmp_nxt_check_list.append(issue_url)
                                continue

                    # get peoples of the issue
                    if check_alert_issues:
                        persons = record['person']
                        own_hi = record['escalation_hierarchy']
                        if ',' in persons:
                            peoples_list = persons.split(',')
                        else:
                            peoples_list = [persons]
                    else:
                        ownership = "assignees"
                        own_hi, peoples_list = self.get_people(repo_name, issue, ownership_index, queues_list, repo_groups, ownership_list, ownership)
                    for p in peoples_list:
                        if p in PEOPLES_BLACKLIST or not p in dc_peoples_list:
                            continue

                        people = peoples[p]
                        #TODO: remove below two if cond
                        if not people.get('work_hours', {}):
                            people['work_hours'] = self.config_json.get('defaults', {})['work_hours']
                        if not people.get('location', ''):
                            people['location'] = self.config_json.get('defaults', {})['location']

                        alert_msg = {
                            "priority": co['priority'],
                            "issue_no": issue['number'],
                            "issue_url": issue['url'],
                            "issue_html_url": issue['html_url'],
                            "issue_title": issue['title'],
                            "constraint_name": co['name'],
                            "queue_name": co['queue'],
                            "constraint_desc": co['message'],
                            "person_name": p,
                            "repo_name": repo_name,
                            "issue_creation_time": issue['created_at'],
                            "repo_group_name": self.repo_group_name,
                            "ownership_hierarchy": own_hi
                        }

                        # check the constraint is pass/not
                        if self.check_constraint(co, issue, people):
                            # check the person is in work_hours
                            if not self.check_person_is_in_work_hours(people):
                                continue

                            if co['continue']:
                                tmp_check_list[issue_url] = True
                            else:
                                tmp_check_list[issue_url] = False

                            record = self.constraints_db.get_failed_check(
                                constraint_name=co['name'],
                                issue_url=issue_url
                            )
                            if record:
                                already_alert.append("{}:{}:{}".format(co['name'], record['person'], issue_url))
                                self.send_alert_to_github(alert_repo, alert_msg, record)
                                # escalation logic
                                last_alert_time = record['datetime']
                                last_escalation = record['escalation_hierarchy']
                                co_follow_ups = {}
                                for d in co['follow_ups']:
                                    co_follow_ups[d['ownership']] = d

                                # iterate over alert msgs
                                for k, v in co_follow_ups.items():
                                    if 'alert' in k:
                                        time_elapsed = v['time_elapsed']
                                        # assignees alert msg before escalate
                                        if last_escalation in OWNERSHIP_HIERARCHY[1:]:
                                            break
                                        elif v['ownership'] in last_escalation.split(','):
                                            continue
                                        p_location = people['location']
                                        p_timezone = self.config_json.get('locations', {}).get(p_location, {}).get('timezone', '')
                                        p_current_time_utc = datetime.datetime.now(timezone(p_timezone)).astimezone(timezone('UTC')).strftime('%Y-%m-%dT%H:%M:%SZ')
                                        if self.calculate_time_constraint(time_elapsed, last_alert_time, p_current_time_utc):
                                            if self.check_person_is_in_work_hours(people):
                                                self.send_escalation_to_alert_issue(alert_repo, v, record)
                                                break

                                last_alert_time = record['datetime']
                                last_escalation = record['escalation_hierarchy']
                                if 'assignees' in last_escalation:
                                    last_escalation = last_escalation.split(',')[0]
                                # iterate over ownership hierarchy
                                escalation_done = False
                                # iterate ownership hierarchy
                                for o in OWNERSHIP_HIERARCHY[(OWNERSHIP_HIERARCHY.index(last_escalation)+1):]:
                                    f = co_follow_ups[o]
                                    time_elapsed = f['time_elapsed']
                                    # iterate over escalation constraints
                                    if "escalate" in f.keys():
                                        ownership = f['ownership']
                                        own_hi, pe_list = self.get_people(
                                            repo_name, issue,
                                            ownership_index,
                                            queues_list,
                                            repo_groups,
                                            ownership_list,
                                            ownership
                                        )
                                        if not pe_list:
                                            continue
                                        for ap in pe_list:
                                            _people = peoples[ap]
                                            #TODO: remove below two if cond
                                            if not _people.get('work_hours', {}):
                                                _people['work_hours'] = self.config_json.get('defaults', {})['work_hours']
                                            if not _people.get('location', ''):
                                                _people['location'] = self.config_json.get('defaults', {})['location']
                                            p_location = _people['location']
                                            p_timezone = self.config_json.get('locations', {}).get(p_location, {}).get('timezone', '')
                                            p_current_time_utc = datetime.datetime.now(timezone(p_timezone)).astimezone(timezone('UTC')).strftime('%Y-%m-%dT%H:%M:%SZ')
                                            if self.calculate_time_constraint(time_elapsed, last_alert_time, p_current_time_utc):
                                                if self.check_person_is_in_work_hours(_people):
                                                    self.send_escalation_to_alert_issue(alert_repo, f, record, pe_list, own_hi)
                                                    escalation_done = True
                                        if escalation_done:
                                            break
                            else:
                                self.send_alert_to_github(alert_repo, alert_msg)

                        else:
                            record = self.constraints_db.get_failed_check(
                                constraint_name=co['name'],
                                issue_url=issue_url
                            )
                            if record:
                                self.close_alert_to_github(alert_repo, alert_msg, record)

                # req a pagination issue url
                if not next_page:
                    break
                else:
                    req_url = next_page['url']

        already_alert = []
        # phase-1 Regular constraint check.
        for repo in final_repo_list:
            repo_name = repo['repo'].full_name
            self.repo_group_name = repo['repo_group']
            for ch in constraints:
                tmp_check_list = {}
                tmp_nxt_check_list = []
                if isinstance(ch, list):
                    for co in ch:
                        co = self.prepare_valid_constraint_dict(co)
                        __check_constraints(self, co=co)
                elif isinstance(ch, dict):
                    co = self.prepare_valid_constraint_dict(ch)
                    __check_constraints(self, co=co)

        # phase-2 check constraints
        #re-check the failed checks table issues
        alerted_issues = self.constraints_db.get_failed_check()
        if alerted_issues:
            for record in alerted_issues:
                cons_name = record['constraint_name']
                issue_url = record['issue_url']
                p_name = record['person']
                if "{}:{}:{}".format(cons_name, p_name, issue_url) in already_alert:
                    continue
                tmp_check_list = {}
                tmp_nxt_check_list = []
                __check_constraints(self, check_alert_issues=True, record=record)

        self.log.info('total_git_api_req_count', type='metric', count=self.request_count)

    def prepare_valid_constraint_dict(self, co):
        final_co = {}
        follow_ups = co.get('follow_ups', [])
        default_time_elapsed = self.config_json.get('defaults', {}).get('time_elapsed', '')
        default_time_elapsed = default_time_elapsed if default_time_elapsed else DEFAULT_TIME_ELAPSED
        check_escalate = [j for j in follow_ups if "escalate" in j.keys()]
        if not follow_ups:
            co['follow_ups'] = [DEFAULT_ESCALATE_CONSTRAINT for i in range(len(OWNERSHIP_HIERARCHY)-1)]
        elif follow_ups and not check_escalate:
            follow_ups.extend([DEFAULT_ESCALATE_CONSTRAINT for i in range(len(OWNERSHIP_HIERARCHY)-1)])
        elif check_escalate:
            config_time_elapsed = follow_ups[-1].get('time_elapsed', '')
            for i in range((len(OWNERSHIP_HIERARCHY)-1)-len(check_escalate)):
                DEFAULT_ESCALATE_CONSTRAINT['time_elapsed'] = config_time_elapsed
                follow_ups.append(DEFAULT_ESCALATE_CONSTRAINT)

        w = []
        l = []
        alert_msg = 1
        for d in co.get('follow_ups', []):
            if not "escalate" in d.keys():
                _d = copy.deepcopy(d)
                _d['ownership'] = "alert{}".format(alert_msg)
                alert_msg += 1
                w.append(_d)
                continue
            l.append(copy.deepcopy(d))

        x = []
        x.extend(w)
        for o, k in zip(OWNERSHIP_HIERARCHY[1:], l):
            k['ownership'] = o
            x.append(k)

        co['follow_ups'] = x
        return co

    def ensure_repo_group_labels(self):
        repo_groups = self.config_json.get('repo_groups', {})
        repo_group_labels = self.config_json.get('repo_group_labels', {})

        for rg_name, rg_list in repo_groups.items():
            existing_labels = []
            for r in rg_list:
                if 'label' in r.keys():
                    continue
                repo_name = r['repo']
                try:
                    repo = self.git.get_repo(repo_name)
                except GithubException as e:
                    if e.data['message'] == "Server Error":
                        raise GithubAPIException("Got Github ServerError Exception")
                    elif e.data['message'] == "Not Found":
                        self.log.exception('invalid_repository_name', repo_name=repo_name)
                    elif 'API rate limit exceeded for user ID' in e.data['message']:
                        self.log.exception('api_rate_limit_exceeded', repo_name=repo_name)
                    sys.exit(1)

                existing_labels = [i.name for i in repo.get_labels()]
                rg_label = repo_group_labels.get(rg_name, {})
                if not rg_label:
                    continue
                rg_label_name = rg_label['name']
                if not rg_label_name in existing_labels:
                    repo.create_label(rg_label_name, rg_label['color'], rg_label['description'])

                for i in repo.get_issues():
                        i.add_to_labels(rg_label_name)

                self.log.info('completed_adding_team_label', repo_name=r, repo_group=rg_name)

    def define_baseargs(self, parser):
        super(GitKanban, self).define_baseargs(parser)

        parser.add_argument('-a', '--github-access-token', type=str,
            help='github account access token to authenticate'
        )
        parser.add_argument('-u', '--username', type=str,
            help='github username'
        )
        parser.add_argument('-p', '--password', type=str,
            help='github password'
        )
        parser.add_argument("--config-file", required=True, type=self.check_file_type,
            help="check the config file ex: conf.json"
        )

def main():
    GitKanban().start()

if __name__ == '__main__':
    main()
