import sys
import json

from github import Github, GithubException

from basescript import BaseScript
from .exceptions import InvalidFileTypeException, GithubServerException

class GitKanban(BaseScript):
    DESC = "A tool to enhance Github issue management with Kanban flow"

    def __init__(self, *args, **kwargs):
        super(GitKanban, self).__init__(*args, **kwargs)

        if self.args.github_access_token:
            self.git = Github(self.args.github_access_token)
        else:
            self.git = Github(self.args.username, self.args.password)

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
        ensure_labels_cmd.add_argument("--org", type=str, help="github organization name")
        ensure_labels_cmd.add_argument("--repo", type=str, help="github repository name")
        ensure_labels_cmd.add_argument("--config-file", required=True, type=self.check_file_type,
            help="github label configuration file"
        )

        # check_constraints arguments
        check_constraints_cmd = subcommands.add_parser('check-constraints',
            help="check the label constraints"
        )
        check_constraints_cmd.set_defaults(func=self.check_constraints)

    def check_file_type(self, path):
        if not path.endswith('.conf'):
            raise InvalidFileTypeException("prefered .conf extension")
        return path

    def ensure_labels(self):
        # check org and repo present in user
        repo_list = []
        if self.args.repo:
            repo_list = [ i.strip() for i in self.args.repo.split(',') ]

        self.repo = []
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
                    self.repo.append(self.git.get_repo(repo_name))
                except GithubException as e:
                    if e.data['message'] == "Server Error":
                        raise GithubServerException("Got Github Server Error Exception")
                    if e.data['message'] == "Not Found":
                        self.log.exception('invalid_repository_name', repo_name=repo_name)
                    sys.exit(1)

        # check repo present in user/org
        if not self.args.org and repo_list:
            try:
                for rn in repo_list:
                    if '/' in rn:
                        self.git.get_repo(rn).name
                        self.repo.append(self.git.get_repo(rn))
                    else:
                        self.repo.append(self.git.get_user().get_repo(rn))
            except GithubException as e:
                if e.data['message'] == "Server Error":
                    raise GithubServerException("Got Github Server Error Exception")
                if e.data['message'] == "Not Found":
                    self.log.exception('invalid_repository_name', repo_name=rn)
                sys.exit(1)

        if self.args.org and not self.args.repo:
            for r in self.git.get_organization(self.args.org).get_repos():
                self.repo.append(r)

        # read lable.conf file
        if self.args.config_file:
            with open(self.args.config_file) as f:
                self.config_json = json.loads(f.read())

        # create label inside repo
        for rep in self.repo:
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
                                    raise GithubServerException("Got Github Server Error Exception")
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
                            raise GithubServerException("Got Github Server Error Exception")
                        label_exist_count += 1

            self.log.info("successfully_created_labels", type="metric",
                repository=rep.name,
                label_created_new=label_new_count,
                label_already_exist=label_exist_count,
                label_edited=label_edited_count,
            )
    def check_constraints(self):
        pass

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

def main():
    GitKanban().start()

if __name__ == '__main__':
    main()
