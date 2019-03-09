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

from pylru import lrucache
from github import Github, GithubException

from basescript import BaseScript
from .constarints_state import ConstraintsStateDB
from .exceptions import InvalidFileTypeException, GithubAPIException, NoDataFoundException

TIMESTAMP_NOW = lambda : datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
ISSUE_URL = 'https://api.github.com/repos/{}/issues'
LRU_CACHE_SIZE = 1000
PEOPLES_BLACKLIST = ["deepcompute-agent", "deep-compute-ops"]

class GitKanban(BaseScript):
    DESC = "A tool to enhance Github issue management with Kanban flow"

    def __init__(self, *args, **kwargs):
        super(GitKanban, self).__init__(*args, **kwargs)

        self.ownership_hierarchy = [
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

        if self.args.github_access_token:
            self.git = Github(self.args.github_access_token)
        else:
            self.git = Github(self.args.username, self.args.password)

        self.constraints = ConstraintsStateDB(self.args.db_dir)

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
        ensure_labels_cmd.add_argument("--config-file", required=True, type=self.check_file_type,
            help="github label configuration file"
        )

        # check_constraints arguments
        check_constraints_cmd = subcommands.add_parser('check-constraints',
            help="check the label constraints"
        )
        check_constraints_cmd.set_defaults(func=self.check_constraints)
        check_constraints_cmd.add_argument("--config-file", required=True, type=self.check_file_type,
            help="check the issue constraints"
        )

    def check_file_type(self, path):
        if not path.endswith('.conf'):
            raise InvalidFileTypeException("prefered .conf extension")
        return path

    def get_repo_list(self):
        # check org and repo present in user
        repo_list = []
        if self.args.repo:
            repo_list = [ i.strip() for i in self.args.repo.split(',') ]

        final_repo_list = []
        if self.args.org:
            user_org = []
            for o in self.git.get_user().get_orgs():
                user_org.append(o.raw_data['login'])
            if not self.args.org in user_org:
                self.log.exception('invalid_organization_name', org_name=self.args.org)
                sys.exit(1)

        if self.args.org and repo_list:
            for rn in repo_list:
                try:
                    repo_name = "{}/{}".format(self.args.org, rn)
                    final_repo_list.append(self.git.get_repo(repo_name))
                except GithubException as e:
                    if e.data['message'] == "Server Error":
                        raise GithubAPIException("Got Github Server Error Exception")
                    if e.data['message'] == "Not Found":
                        self.log.exception('invalid_repository_name', repo_name=repo_name)
                    sys.exit(1)

        # check repo present in user/org
        if not self.args.org and repo_list:
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
                if e.data['message'] == "Not Found":
                    self.log.exception('invalid_repository_name', repo_name=rn)
                sys.exit(1)

        if self.args.org and not self.args.repo:
            for r in self.git.get_organization(self.args.org).get_repos():
                final_repo_list.append(r)

        return final_repo_list

    def ensure_labels(self):
        final_repo_list = self.get_repo_list()

        # read lable.conf file
        if self.args.config_file:
            with open(self.args.config_file) as f:
                self.config_json = json.loads(f.read())

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

    def get_people(self, repo_name, issue, ownership_index, queues, repo_groups, ownership_list):
        queues_list = queues.values()
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
        for op in final_ownership_list:
            # check repo_group specific config
            if "repo_group" in op.keys():
                for r in repo_groups[op["repo_group"]]:
                    if repo_name == r['repo']:
                        label = r.get('label', '')
                        assignee = r.get('assignee', '')
                        if label and assignee:
                            if not label in issue_labels or not assignee in issue_assignees:
                                return
            #TODO: if we miss order the keys in the config file
            key = '-'.join([k.replace('_', '-') for k in op.keys() if not k == 'people'])
            ownership_people[key] = op['people']

        # add assignees of a issue
        if issue_assignees:
            ownership_people['assignees'] = issue_assignees

        # get the people based on our ownership hierarchy
        people = []
        for oh in self.ownership_hierarchy:
            if oh in ownership_people.keys():
                people = ownership_people[oh]
                break

        if not people:
            people.extend(self.system_owners)

        return people

    def check_last_constraint_executed(self, co, last_executed_record):
        past = last_executed_record['last_dt_executed']
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
            if data['message'] == 'Not Found':
                raise NoDataFoundException

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

        diff_time = relativedelta(parser.parse(p_current_time_utc), parser.parse(issue_created_at))
        months = diff_time.months
        days = diff_time.days
        hours = diff_time.hours
        #TODO: check year, months having 31, holidays, leapyear,..
        total_hours = int(((months * 30) * 24) + (days * 24) + hours)
        if total_hours > int(c_hours):
            return True

        return False

    def check_constraint(self, constraint, issue, people):
        if constraint['queue'] == "inbox":
            issue_data = issue
        else:
            # req a issue comments url to get the last comment info
            comments_url = issue['comments_url']
            params = {"per_page": 100}
            res_obj, data = self.make_request(comments_url, params)
            last_page = res_obj.links.get('last', {}).get('url', '')
            if last_page:
                com_res_obj, data = self.make_request(last_page, params)

            if not data:
                # when issue moved from inbox -> ready/next/in-progress and vice versa without any comments.
                if constraint['queue'] in ['next', 'ready', 'in-progress']:
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
        #TODO: Before validate the config file, fill with default values, with all keys
        #TODO: validate the config file
        # read lable.conf file
        if self.args.config_file:
            with open(self.args.config_file) as f:
                self.config_json = json.loads(f.read())

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
        queues = self.config_json.get('queues', {})
        repo_groups = self.config_json.get('repo_groups', {})
        peoples = self.config_json.get('people', {})
        dc_peoples_list = peoples.keys()
        # get all the repo's from the user specs
        final_repo_list = self.get_repo_list()
        for repo in final_repo_list:
            repo_name = repo.full_name
            for ch in checks:
                tmp_check_list = {}
                tmp_nxt_check_list = []
                for co in ch:
                    co_queue_name = co.get('queue', '')
                    actual_q_name = queues[co_queue_name]
                    if not actual_q_name:
                        params = {} # for inbox case
                    else:
                        params = {"labels": actual_q_name}

                    params['per_page'] = 100
                    # req a repo url to get the issues, default will get only open issues
                    #TODO: check if there are issues pagination
                    req_url = ISSUE_URL.format(repo_name)
                    # req a issue url with pagination
                    while True:
                        resp_obj, issues_list = self.make_request(req_url, params=params)
                        next_page = resp_obj.links.get('next', {})

                        if co_queue_name == "inbox":
                            issues_list = [i for i in issues_list if not i['labels']]

                        for issue in issues_list:
                            issue_url = issue['url']
                            # skip the issues which are passed in the before constraint of first run
                            if issue_url in tmp_check_list.keys():
                                if not tmp_check_list[issue_url]:
                                    continue

                            if issue_url in tmp_nxt_check_list:
                                continue

                            # check last executed from sqlite
                            co_name = co['name']
                            co_feruency = co['frequency']
                            co_continue = co['continue']
                            check_co_id = "{}:{}".format(co_name, issue_url)
                            last_executed_record = self.constraints.get_constraint(check_co_id)
                            if not last_executed_record:
                                co_con = 1 if co_continue else 0
                                self.constraints.new_constraint(check_co_id, TIMESTAMP_NOW(), co_con)
                            elif not self.check_last_constraint_executed(co, last_executed_record):
                                if not last_executed_record['co_continue']:
                                    tmp_nxt_check_list.append(issue_url)
                                continue

                            # get peoples of the issue
                            peoples_list = self.get_people(repo_name, issue, ownership_index, queues, repo_groups, ownership_list)
                            for p in peoples_list:
                                if p in PEOPLES_BLACKLIST or not p in dc_peoples_list:
                                    continue

                                people = peoples[p]
                                # remove below two lines
                                people['work_hours'] = self.config_json.get('defaults', {})['work_hours']
                                people['location'] = self.config_json.get('defaults', {})['location']
                                # check the constraint is pass/not
                                if self.check_constraint(co, issue, people):
                                    if co_continue:
                                        tmp_check_list[issue_url] = True
                                    else:
                                        tmp_check_list[issue_url] = False
                                    self.log.info("got_alert", priority=co['priority'],
                                        issue_no=issue['number'], issue_url=issue['url'],
                                        queue=co['queue'], constraint_name=co['name'], person_name=p,
                                        repo_name=repo_name, issue_title=issue['title'],
                                        issue_creation_time=issue['created_at'],
                                    )

                        # req a pagination issue url
                        if not next_page:
                            break
                        else:
                            req_url = next_page['url']


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
            help="github repository name"
        )
        parser.add_argument("--db-dir",
            default=os.path.join(os.getcwd(), "constraints.db"),
            help="dir for sessions db info",
        )

def main():
    GitKanban().start()

if __name__ == '__main__':
    main()
