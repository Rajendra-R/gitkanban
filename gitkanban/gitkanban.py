import sys
import json
import os
import requests
import datetime
import dateutil
import calendar
import hashlib
from pytz import timezone
from dateutil import parser
from dateutil.relativedelta import relativedelta

from json2html import *
from pylru import lrucache
from github import Github, GithubException

from basescript import BaseScript
from .constarints_state import ConstraintsStateDB
from .exceptions import *

TIMESTAMP_NOW = lambda : datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
ISSUE_URL = 'https://api.github.com/repos/{}/issues'
LRU_CACHE_SIZE = 1000
PEOPLES_BLACKLIST = ["deepcompute-agent", "deep-compute-ops"]

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

        self.constraints = ConstraintsStateDB(self.args.db)

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

        # ensure_repo_group_labels arguments
        ensure_repo_group_labels = subcommands.add_parser('ensure-repo-group-labels',
            help="create the repo_group labels to the repo in that group"
        )
        ensure_repo_group_labels.set_defaults(func=self.ensure_repo_group_labels)

    def send_to_github_alert(self, alert_repo, alert_msg):
        # send alert to github
        try:
            data = json2html.convert(json = alert_msg)
            body = "### Read-Me:\nIssue-url - {}\n{}\n".format(alert_msg['issue_html_url'], data)
            labels=[
                '{}-priority'.format(alert_msg['priority']),
                '{}-repo'.format(alert_msg['repo_name']),
                '{}-queue'.format(alert_msg['queue_name']),
                '{}-constraint'.format(alert_msg['constraint_name'])
            ]
            if alert_msg['repo_group_name']:
                labels.append('{}-repo-group'.format(alert_msg['repo_group_name']))
            #TODO: check it is making multiple github api calls?
            alert_issue = alert_repo.create_issue(
                title="Gitkanban:{}-{}#{}".format(alert_msg['constraint_name'], alert_msg['repo_name'], alert_msg['issue_no']),
                body=body,
                assignees=[alert_msg['person_name']],
                labels=labels
            )
            # insert record to table
            self.constraints.insert_failed_check(
                alert_msg['constraint_name'],
                alert_msg['person_name'],
                alert_msg['issue_url'],
                TIMESTAMP_NOW(),
                alert_issue.number
            )
            self.log.info('successfully_inserted_alert_to_github')
        except GithubException as e:
            if e.data['message'] == "Validation Failed":
                self.log.exception('got_error_while_inserting_alert', error=e.data['errors'])

    def check_file_type(self, path):
        if not path.endswith('.json'):
            raise InvalidFileTypeException("prefered .json extension")
        return path

    def check_db_type(self, path):
        if not path.endswith('.db'):
            raise InvalidDBTypeException("prefered .db extension")
        return path

    def get_repo_list(self, args_org, args_repo):
        # check org and repo present in user
        repo_list = []
        if args_repo:
            repo_list = [ i.strip() for i in args_repo.split(',') ]

        final_repo_list = []
        if args_org:
            user_org = []
            for o in self.git.get_user().get_orgs():
                user_org.append(o.raw_data['login'])
            if not args_org in user_org:
                self.log.exception('invalid_organization_name', org_name=args_org)
                sys.exit(1)

        if args_org and repo_list:
            for rn in repo_list:
                try:
                    repo_name = "{}/{}".format(args_org, rn)
                    final_repo_list.append(self.git.get_repo(repo_name))
                except GithubException as e:
                    if e.data['message'] == "Server Error":
                        raise GithubAPIException("Got Github Server Error Exception")
                    elif e.data['message'] == "Not Found":
                        self.log.exception('invalid_repository_name', repo_name=repo_name)
                    elif 'API rate limit exceeded for user ID' in e.data['message']:
                        self.log.exception('api_rate_limit_exceeded', repo_name=repo_name)
                    sys.exit(1)

        # check repo present in user/org
        if not args_org and repo_list:
            try:
                for rn in repo_list:
                    if '/' in rn:
                        self.git.get_repo(rn).name
                        final_repo_list.append(self.git.get_repo(rn))
                    else:
                        final_repo_list.append(self.git.get_user().get_repo(rn))
            except GithubException as e:
                if e.data['message'] == "Server Error":
                    raise GithubAPIException("Got Github Server Error Exception")
                elif e.data['message'] == "Not Found":
                    self.log.exception('invalid_repository_name', repo_name=rn)
                elif 'API rate limit exceeded for user ID' in e.data['message']:
                    self.log.exception('api_rate_limit_exceeded', repo_name=rn)
                sys.exit(1)

        if args_org and not args_repo:
            for r in self.git.get_organization(args_org).get_repos():
                final_repo_list.append(r)

        return final_repo_list

    def ensure_labels(self):
        final_repo_list = self.get_repo_list(self.args.org, self.args.repo)

        # create/update/delete label inside repo
        for rep in final_repo_list:
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
                                for ali in aka_label_issues:
                                    ali.add_to_labels(k)
                                    ali.remove_from_labels(aka)
                                rep.get_label(aka).delete()

                if not edit_flag:
                    try:
                        if desc:
                            rep.create_label(label_name, color, desc)
                        else:
                            rep.create_label(label_name, color)
                        label_new_count += 1
                    except GithubException as e:
                        if e.data['message'] == "Server Error":
                            raise GithubAPIException("Got Github Server Error Exception")
                        label_exist_count += 1

            self.log.info("successfully_created_labels", type="metric",
                repository=rep.name,
                label_created_new=label_new_count,
                label_already_exist=label_exist_count,
                label_edited=label_edited_count,
            )

    def get_people(self, repo_name, issue, ownership_index, queues_list, repo_groups, ownership_list):
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
            if repo_name in [r['repo'] for r in rv]:
                check_issue_index.append('repo_group:{}'.format(rn))

        # get all the ownership indexes from the config file of a issue
        issue_ownership_index = []
        for c in check_issue_index:
            issue_ownership_index.append(ownership_index.get(c, None))

        issue_ownership_index = list(filter(None, issue_ownership_index)) # [{0,1,2}, {1,2}, {2,3}]

        issue_ownership_intersection = set()
        if issue_ownership_index:
            issue_ownership_intersection = set.intersection(*issue_ownership_index) # {1,2}

        # get ownership dic of a index from the config ownership [{}, {}]
        final_ownership_list = []
        for p in issue_ownership_intersection:
            final_ownership_list.append(ownership_list[p])

        # get the selected people from the config ownership based on issue
        ownership_people = {}
        self.repo_group_name = None
        for op in final_ownership_list:
            # check repo_group specific config
            if "repo_group" in op.keys():
                for r in repo_groups[op["repo_group"]]:
                    if repo_name == r['repo']:
                        self.repo_group_name = op["repo_group"]
                        label = r.get('label', '')
                        assignee = r.get('assignee', '')
                        if label and assignee:
                            if not label in issue_labels or not assignee in issue_assignees:
                                return
            #TODO: if we miss order the keys in the config file
            key = '-'.join([k.replace('_', '-') for k in op.keys() if not k == 'people'])
            ownership_people[key] = op['people']

        #import pdb;pdb.set_trace()
        # add assignees of a issue
        if issue_assignees:
            ownership_people['assignees'] = issue_assignees

        # get the people based on our ownership hierarchy
        people = []
        for oh in OWNERSHIP_HIERARCHY:
            if oh in ownership_people.keys():
                people = ownership_people[oh]
                break

        if not people:
            people.extend(self.system_owners)

        return people

    def check_last_constraint_executed(self, co, last_executed_record):
        past = last_executed_record['datetime']
        current = TIMESTAMP_NOW()

        start = datetime.datetime.strptime(past, '%Y-%m-%d %H:%M:%S')
        end = datetime.datetime.strptime(current, '%Y-%m-%d %H:%M:%S')

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
            return (resp_obj, data)

        resp_obj = requests.get(url, params=params)
        data = resp_obj.json()

        if isinstance(data, dict):
            if data.get('message', '') == 'Not Found':
                raise NoDataFoundException
            elif data.get('message', '') == "Server Error":
                raise GithubAPIException("Got Github Server Error Exception")

            data = [data]

        self.lru[_id] = (resp_obj, data)
        return (resp_obj, data)

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
        minutes = diff_time.minutes
        #TODO: check year, months having 31, holidays, leapyear,..
        total_hours = int(((months * 30) * 24) + (days * 24) + hours)
        if total_hours > int(c_hours):
            return True

        return False

    def check_constraint(self, constraint, issue, people):
        # req a issue comments url to get the last comment info
        comments_url = issue['comments_url']
        params = {"per_page": 100}
        res_obj, data = self.make_request(comments_url, params)
        last_page = res_obj.links.get('last', {}).get('url', '')
        if last_page:
            com_res_obj, data = self.make_request(last_page, params)

        if not data:
            # when issue moved from inbox <-> ready/next/in-progress and vice versa without any comments.
            if constraint['queue'] in ['inbox', 'next', 'ready', 'in-progress']:
                issue_data = issue
            else:
                #TODO: handle this properly
                return False
        else:
            issue_data = data[-1]

        issue_created_at = issue_data['created_at']
        issue_updated_at = issue_data['updated_at']

        time_constraint = constraint.get('time_since_creation', '') or constraint.get('time_since_activity', '')

        # check the person is in working hours
        # based on our custom timezone logic of a person change the issue created time
        issue_created_at = self.get_issue_created_datetime(issue_created_at, people)
        if self.calculate_time_constraint(time_constraint, issue_created_at, self.p_current_time_utc):
            return True

        return False

    def check_constraints(self):
        # prepare owndership index from the given config file
        # d = [{'a': 'a1', 'b': 'b1', 'c': 'c1'}, {'a': 'a1', 'd': 'd1'}, {'b': 'b1'}, {'e': 'e1'}]
        # {'a:a1': {0, 1}, 'b:b1': {0, 2}, 'c:c1': {0}, 'd:d1': {1}, 'e:e1': {3}}
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


        checks = self.config_json.get('checks', [])
        co_info = {}
        for i in checks:
            for ci in i:
                co_info[ci['name']] = ci
        queues = self.config_json.get('queues', {})
        queues_list = queues.values()
        repo_groups = self.config_json.get('repo_groups', {})
        peoples = self.config_json.get('people', {})
        dc_peoples_list = peoples.keys()
        # get all the repo's from the user specs
        alert_repo = self.get_repo_list(self.args.org, self.args.alert_repo)[0]
        final_repo_list = self.get_repo_list(self.args.org, self.args.repo)
        already_alert = []
        for repo in final_repo_list:
            repo_name = repo.full_name
            for ch in checks:
                tmp_check_list = {}
                tmp_nxt_check_list = []
                #import pdb;pdb.set_trace()
                #TODO: implement flag
                for co in ch:
                    def __check_constraints(self, co, p_name=None, check_alert_issues=False, issue_url=None):
                        if check_alert_issues:
                            co = co_info[co]
                        co_queue_name = co.get('queue', '')
                        actual_q_name = queues[co_queue_name]
                        if not actual_q_name:
                            params = {} # for inbox case
                        else:
                            params = {"labels": actual_q_name}

                        params['per_page'] = 100
                        if not check_alert_issues:
                            # req a repo url to get the issues, default will get only open issues
                            req_url = ISSUE_URL.format(repo_name)
                        else:
                            req_url = issue_url
                        # req a issue url with pagination
                        while True:
                            resp_obj, issues_list = self.make_request(req_url, params=params)
                            next_page = resp_obj.links.get('next', {})

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

                                if not check_alert_issues:
                                    # check last executed from sqlite
                                    co_name = co['name']
                                    co_feruency = co['frequency']
                                    co_continue = co['continue']
                                    check_co_id = "{}:{}".format(co_name, issue_url)
                                    last_executed_record = self.constraints.get_failed_check(constraint_name=co_name, 
                                        issue_url=issue_url
                                    )
                                    if last_executed_record:
                                        if not self.check_last_constraint_executed(co, last_executed_record):
                                            if not co_continue:
                                                tmp_nxt_check_list.append(issue_url)
                                            continue

                                # get peoples of the issue
                                peoples_list = self.get_people(repo_name, issue, ownership_index, queues_list, repo_groups, ownership_list)
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
                                        "person_name": p,
                                        "repo_name": repo_name,
                                        "issue_creation_time": issue['created_at'],
                                        "repo_group_name": self.repo_group_name
                                    }

                                    # check the constraint is pass/not
                                    if self.check_constraint(co, issue, people):
                                        if co['continue']:
                                            tmp_check_list[issue_url] = True
                                        else:
                                            tmp_check_list[issue_url] = False

                                        record = self.constraints.get_failed_check(
                                            constraint_name=co['name'],
                                            person=p, issue_url=issue_url
                                        )
                                        if record:
                                            already_alert.append("{}:{}:{}".format(co['name'], p, issue_url))
                                        else:
                                            self.send_to_github_alert(alert_repo, alert_msg)

                                    else:
                                        record = self.constraints.get_failed_check(
                                            constraint_name=co['name'],
                                            person=p, issue_url=issue_url
                                        )
                                        if record:
                                            get_alert_issue = alert_repo.get_issue(number=record['alert_issue_id'])
                                            get_alert_issue.create_comment(body="**Gitkanban:** Auto-Resolved")
                                            get_alert_issue.edit(state='closed')
                                            self.constraints.delete_failed_check(co['name'], p, issue_url)
                                            alert_msg['alert_status'] = 'resolved'
                                            self.log.info('successfully_closed_alert_to_github', **alert_msg)

                            # req a pagination issue url
                            if not next_page:
                                break
                            else:
                                req_url = next_page['url']

                __check_constraints(self, co)

        #re-check the trigger issues
        trigger_issues = self.constraints.get_failed_check()
        if trigger_issues:
            for ti in trigger_issues:
                cons_name = ti['constraint_name']
                issue_url = ti['issue_url']
                p_name = ti['person']
                if "{}:{}:{}".format(cons_name, p_name, issue_url) in already_alert:
                    continue
                tmp_check_list = {}
                tmp_nxt_check_list = []
                __check_constraints(self, cons_name, p_name, check_alert_issues=True, issue_url=issue_url)

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

        parser.add_argument('-auth', '--github-access-token', type=str,
            help='github account access token to authenticate'
        )
        parser.add_argument('-u', '--username', type=str,
            help='github username'
        )
        parser.add_argument('-p', '--password', type=str,
            help='github password'
        )
        parser.add_argument('-o', '--org', type=str,
            help="github organization name"
        )
        parser.add_argument('-r', '--repo', type=str,
            help="github repository name ex: 'abc'(or)'deep/abc'(or)'deep/a,deep/b,deep/c'"
        )
        parser.add_argument('-ar', '--alert-repo', type=str,
            help="github alert repository name ex: 'alerts'",
        )
        parser.add_argument("--db", required=True, type=self.check_db_type,
            help="check the db file name ex: state.db or /tmp/state.db",
        )
        parser.add_argument("--config-file", required=True, type=self.check_file_type,
            help="check the config file ex: conf.json"
        )

def main():
    GitKanban().start()

if __name__ == '__main__':
    main()
