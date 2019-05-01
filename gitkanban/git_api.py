import json
from github import Github


# create a Github instance using token or git = Github(user, pass)
token = 'YOUR TOKEN'
git = Github(token)


def get_config_file():
    with open('local/gitkanban.json') as f:
        config_file = json.loads(f.read())

    return config_file


# gets all repositories from config file
#   :return: list of Repository objects
def get_all_repos():
    # config_file = self.args.config_json
    config_file = get_config_file()

    # get repos from config file
    repo_groups = config_file['repo_groups']

    # get all repos from each repo_group
    return [git.get_repo(str(*i.values())) for k, v in repo_groups.items() for i in v]


# add Organization row to session by creating or find existing
#   :return: Organization row
def get_organization(repo, session):

    # get organization of repo
    org_git = repo.organization
    org_row = None  # do I make condition for repo WITHOUT an organization?

    # assign existing organization
    if Organization.query.filter_by(login=org_git.login).first():
        org_row = Organization.query.filter_by(login=org_git.login).first()
    else:  # if it doesn't exist, create & add it
        org_row = Organization(login=org_git.login, name=org_git.name,
                               description=org_git.description, email=org_git.email)
        session.add(org_row)

    return org_row


# add User row to session by creating or find existing
#   :return: list of User rows
def get_user(repo=None, issue_comment=None):

    users = None

    # if getting user from repo
    if repo:
        pass

    # if getting user from issue_comment
    if issue_comment:
        pass

    return users


def get_assignees(issue):

    assignees = issue.assignees
    return assignees


# add Label row to session by creating or find existing
#   :return: Label row
def get_labels(issue):

    labels = issue.labels
    return labels


# TODO: add issue_user_assignee_rel_table and issue_label_rel_table
#       issue assignees and labels
#       labels
#       possibly make separate functions for each model instead of nested loops
def populate_db(session):

    # get all repos
    repos = get_all_repos()

    # for each repo, populate tables by adding rows
    for repo in repos:

        # get repo's Users

        # get repo's Organization
        organization_row = get_organization(repo, session)

        # create Repository row and add to session
        repository_row = Repository(name=repo.name, description=repo.description,
                                    owner_type=repo.owner.type, owner_id=repo.owner.id,
                                    organization=organization_row)
        session.add(repository_row)

        # get open issues of repo
        open_issues = repo.get_issues(state='open')

        for issue in open_issues:

            user = issue.closed_by
            assignees = get_assignees(issue)
            labels = get_labels(issue)

            # create Issue row and add to session
            issue_row = Issue(repository=repository_row, number=issue.number,
                              title=issue.title, body=issue.body,
                              state=issue.state, closed_at=issue.closed_at,
                              assignees=assignees, labels=labels, closed_by=user)
            session.add(issue_row)

            # for each issue get issue comments
            for comment in issue.get_comments():

                # add issue_comment_row
                commenter = comment.user
                issue_comment_row = IssueComment(issue=issue_row, user=commenter,
                                                 body=comment.body)
                session.add(issue_comment_row)

    # commit all to db
    session.commit()


# print organization attributes: login, name, description, email
def get_organization_git(repo):
    # print organization's attributes that we need
    print(org.login)
    print(org.name)
    print(org.description)
    print(org.email)


# print comments of an issue and get it's attributes: issue_id, user_id, body
def _get_comments_git(open_issue):

    for comment in open_issue.get_comments():
        print(comment.body)


# print repo attributes: repository_id, number, title, body, state,
def get_issues_git(repo):

    open_issues = repo.get_issues(state='open')

    for open_issue in open_issues[:4]:
        print(open_issue.number)
        print(open_issue.title)
        print(open_issue.body)

        _get_comments_git(open_issue)


# print user attributes by repo: name, login, company, location, email, avatar_url
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


# print user attributes by repo: name, login, company, location, email, avatar_url
def get_labels_git():
    labels = repo.get_labels()
    for label in labels:
        print(label.name)
        print(label.description)
        print(label.color)
