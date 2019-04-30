import json
from github import Github


# create a Github instance using token or user/pass
token = 'YOUR TOKEN'
git = Github(token)  # or git = Github(user, pass)


""" Gets all repositories from config file
    :return:
        list of all repositories as Github Repository objects
"""
def get_all_repos():
    # get config file (self.args.config_json)
    with open('local/gitkanban.json') as f:
        config_file = json.loads(f.read())

    # get repos from config file
    repo_groups = config_file['repo_groups']

    # get all repos from each repo_group
    return [git.get_repo(str(*i.values())) for k, v in repo_groups.items() for i in v]


""" Get organization attributes: login, name, description, email
    :return:
        nothing returned, prints attributes
"""
def get_organization_git(repo):
    # print organization's attributes that we need
    print(org.login)
    print(org.name)
    print(org.description)
    print(org.email)

    # create Organization model and save to db
    # organization = Organization(login=org.login, name=org.name,
    #     description=org.description, email=org.email)

    # return organization


""" Get comments of an issue and get it's attributes: issue_id, user_id, body
    :param: Open Issue object
    :return:
        nothing returned, prints attributes
"""
def _get_comments_git(open_issue):

    for comment in open_issue.get_comments():
        print(comment.body)


""" Get repo attributes: repository_id, number, title, body, state,
    closed_at, closed_by_id
    :return:
        nothing returned, prints attributes
"""
def get_issues_git(repo):

    open_issues = repo.get_issues(state='open')

    for open_issue in open_issues[:4]:
        print(open_issue.number)
        print(open_issue.title)
        print(open_issue.body)

        _get_comments_git(open_issue)


""" Get user attributes by repo: name, login, company, location,
    email, avatar_url
    :return:
        nothing returned, prints attributes
"""
def get_user_git():

    collaborators = repo.get_collaborators()

    for collaborator in collaborators:
        print(collaborator.name)
        print(collaborator.login)
        print(collaborator.company)
        print(collaborator.location)
        print(collaborator.email)
        print(collaborator.avatar_url)
        print()


""" Get user attributes by repo: name, login, company, location,
    email, avatar_url
    :return:
        nothing returned, prints attributes
"""
def get_repo_labels():

    labels = repo.get_labels()
    for label in labels:
        print(label.name)
        print(label.description)
        print(label.color)

# TODO: add issue_user_assignee_rel_table and issue_label_rel_table
#       issue assignees and labels
#       issue comments
#       labels
#       possibly make separate functions for each model instead of nested loops

def add_commit():
    # get all repos
    repos = get_all_repos()

    # for each repo save attributes to db and assign organization owner
    for repo in repos:
        # get organization of repo, create Organization, add to db
        org = repo.organization  # do I make condition for repo WITHOUT an organization
        o = Organization(login=org.login, name=org.name,
                         description=org.description, email=org.email)

        # assign existing organization (for relationship to same Organization)
        if Organization.query.filter_by(login=org.login).first():
            o = Organization.query.filter_by(login=org.login).first()
        else:  # if it doesn't exist add it
            session.add(o)

        # create Repository, add to db
        r = Repository(name=repo.name, description=repo.description,
                       owner_type=repo.owner.type, owner_id=repo.owner.id,
                       organization=o)
        session.add(r)

        # get issues of repo, create Issue, add to db
        open_issues = repo.get_issues(state='open')
        # for each issue save attributes to db and assign repository owner
        for issue in open_issues:
            # get closed by
            u = issue.closed_by
            # assign existing issue (for relationship to same Issue)
            if Issue.query.filter_by(closed_by=u.login).first():
                u = Issue.query.filter_by(closed_by=u.login).first()
            else:  # if it doesn't exist add it
                session.add(u)

            i = Issue(repository=r, number=issue.number, title=issue.title,
                      body=issue.body, state=issue.state,
                      closed_at=issue.closed_at, closed_by=u)  # add assignees, labels

            # for each issue get issue comments
            for comment in issue.get_comments():
                c = IssueComment()

        # commit all to db
        session.commit()


"""
Webhook boilerplate code
"""
# from __future__ import print_function
#
# from wsgiref.simple_server import make_server
# from pyramid.config import Configurator
# from pyramid.view import view_config, view_defaults
# from pyramid.response import Response
# from github import Github
#
# ENDPOINT = "webhook"
#
#
# @view_defaults(
#     route_name=ENDPOINT, renderer="json", request_method="POST"
# )
# class PayloadView(object):
#     """
#     View receiving of Github payload. By default, this view it's fired only if
#     the request is json and method POST.
#     """
#
#     def __init__(self, request):
#         self.request = request
#         # Payload from Github, it's a dict
#         self.payload = self.request.json
#
#     @view_config(header="X-Github-Event:push")
#     def payload_push(self):
#         """This method is a continuation of PayloadView process, triggered if
#         header HTTP-X-Github-Event type is Push"""
#         print("No. commits in push:", len(self.payload['commits']))
#         return Response("success")
#
#     @view_config(header="X-Github-Event:pull_request")
#     def payload_pull_request(self):
#         """This method is a continuation of PayloadView process, triggered if
#         header HTTP-X-Github-Event type is Pull Request"""
#         print("PR", self.payload['action'])
#         print("No. Commits in PR:", self.payload['pull_request']['commits'])
#
#         return Response("success")
#
#     @view_config(header="X-Github-Event:ping")
#     def payload_else(self):
#         print("Pinged! Webhook created with id {}!".format(self.payload["hook"]["id"]))
#         return {"status": 200}
#
#
# def create_webhook():
#     """ Creates a webhook for the specified repository.
#
#     This is a programmatic approach to creating webhooks with PyGithub's API. If you wish, this can be done
#     manually at your repository's page on Github in the "Settings" section. There is a option there to work with
#     and configure Webhooks.
#     """
#
#     USERNAME = ""
#     PASSWORD = ""
#     OWNER = ""
#     REPO_NAME = ""
#     EVENTS = ["push", "pull_request"]
#     HOST = ""
#
#     config = {
#         "url": "http://{host}/{endpoint}".format(host=HOST, endpoint=ENDPOINT),
#         "content_type": "json"
#     }
#
#     g = Github(USERNAME, PASSWORD)
#     repo = g.get_repo("{owner}/{repo_name}".format(owner=OWNER, repo_name=REPO_NAME))
#     repo.create_hook("web", config, EVENTS, active=True)
#
#
# if __name__ == "__main__":
#     config = Configurator()
#
#     create_webhook()
#
#     config.add_route(ENDPOINT, "/{}".format(ENDPOINT))
#     config.scan()
#
#     app = config.make_wsgi_app()
#     server = make_server("0.0.0.0", 80, app)
#     server.serve_forever()
