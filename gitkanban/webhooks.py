import json
import requests


def _is_trigger(event, action):
    # check if the webhook event/action is a trigger
    return event in triggers.keys() and action in triggers[event]


def _get_trigger():
    # get the event and action if it is a trigger
    event, action = headers['x-github-event'], body['action']

    if _is_trigger(event, action):
        return event, action
    else:
        return None, None


def trigger_handler():
    # handle the event/action by passing to corresponding functions
    event, action = _get_trigger()
    handle = {
        'organization': organization,
        'repository': repository,
        'issues': issues,
        'issue_comment': issue_comment,
        'label': label
    }

    # handle important event and action, else don't do anything
    if event and action:
        handle[event](action)


def add_get_user(user):
    # return User if exists, else create and return
    r = requests.get(user['url'])
    user = r.json()

    if session.query(User).filter_by(node_id=user['node_id']).first():
        return session.query(User).filter_by(node_id=user['node_id']).first()
    else:
        user_row = User(name=user['name'], login=user['login'],
                        company=user['company'], location=user['location'],
                        email=user['email'], avatar_url=user['avatar_url'],
                        node_id=user['node_id'])
        self.session.add(user_row)
        self.session.commit()
        return user_row


def add_get_label(label):
    # return Label if exists, else create and return

    if session.query(Label).filter_by(node_id=label['node_id']).first():
        return session.query(Label).filter_by(node_id=label['node_id']).first()
    else:
        label_row = Label(name=label['name'], description=None,
                          color=label['color'], node_id=label['node_id'])

        self.session.add(label_row)
        self.session.commit()
        return label_row


def organization(action):
    # organization: deleted, renamed

    print(f'organization event, {action} action')

    # for query by node_id
    org_node = body['organization']['node_id']

    if action == 'deleted':
        session.query(Organization).filter_by(node_id=org_node).delete()
        session.commit()

    if action == 'renamed':
        org = session.query(Organization).get(node_id=org_node)
        org.name = body['organization']['name']
        session.commit()


def repository(action):
    # repository: created, renamed, edited, deleted

    print(f'repository event, {action} action')

    if action == 'created':
        # get repo's Organization
        r = requests.get(body['repository']['owner']['organizations_url'])
        org_node = r.json()['node_id']
        organization_row = session.query(Organization).filter_by(node_id=org_node).first()

        # create Repository row and add to session
        repository_row = Repository(name=body['repository']['name'], description=body['repository']['description'],
                                    owner_type=body['repository']['owner']['type'], owner_id=body['repository']['owner']['id'],
                                    organization=organization_row, node_id=body['repository']['node_id'])
        session.add(repository_row)

        # create web hook for this repository
        create_webhook(repo)

        session.commit()

    if action == 'renamed':
        repo_node = body['repository']['node_id']
        repo = session.query(Repository).get(node_id=repo_node)
        repo.name = body['repository']['name']
        session.commit()

    if action == 'edited':
        repo_node = body['repository']['node_id']
        repo = session.query(Repository).get(node_id=repo_node)
        # change and commit all attributes
        repo.description = body['repository']['description']
        repo.owner_id = body['repository']['owner']['id']
        repo.owner_type = body['repository']['owner']['type']
        session.commit()

    if action == 'deleted':
        repo_node = body['repository']['node_id']
        session.query(Repository).filter_by(node_id=repo_node).delete()
        session.commit()


def issues(action):
    # issues: opened, edited, deleted, transferred, closed, reopened, assigned, unassigned, labeled, unlabeled

    print(f'issues event, {action} action')

    if action == 'opened':
        repo_node = body['repository']['node_id']
        repo_row = session.query(Repository).filter_by(node_id=repo_node).first()
        # create Issue row and add to session
        issue_row = Issue(number=body['issue']['number'], title=body['issue']['title'],
                          body=body['issue']['body'], state=body['issue']['state'],
                          closed_at=body['issue']['closed_at'], closed_by=None,
                          repository=repo_row, node_id=body['issue']['node_id'])
        session.add(issue_row)
        session.commit()

    if action == 'edited':
        issue_node = body['issue']['node_id']
        issue = session.query(Issue).get(node_id=issue_node)
        # change and commit all attributes
        issue.title = body['issue']['title']
        session.commit()

    if action == 'deleted' or 'transferred':
        issue_node = body['issue']['node_id']
        issue = session.query(Issue).filter_by(node_id=issue_node).delete()
        session.commit()

    if action == 'closed':
        issue_node = body['issue']['node_id']
        issue = session.query(Issue).get(node_id=issue_node)
        # change and commit all attributes
        issue.state = body['issue']['state']
        issue.closed_at = body['issue']['closed_at']
        issue.closed_by = add_get_user(body['issue']['user'])
        session.commit()

    if action == 'reopened':
        issue_node = body['issue']['node_id']
        issue = session.query(Issue).get(node_id=issue_node)
        # change and commit all attributes
        issue.title = body['issue']['title']
        session.commit()

    if action == 'assigned':
        issue_node = body['issue']['node_id']
        issue = session.query(Issue).get(node_id=issue_node)
        # change and commit all attributes
        for assignee in body['issue']['assignees']:
            issue.assignees.append(add_get_user(assignee))
        session.commit()

    if action == 'unassigned':
        issue_node = body['issue']['node_id']
        issue = session.query(Issue).get(node_id=issue_node)
        # change and commit all attributes
        issue.assignees.remove(add_get_user(body['assignee']))
        session.commit()

    if action == 'labeled':
        issue_node = body['issue']['node_id']
        issue = session.query(Issue).get(node_id=issue_node)
        # change and commit all attributes
        for label in body['issue']['labels']:
            issue.labels.append(add_get_label(label))
        session.commit()

    if action == 'unlabeled':
        issue_node = body['issue']['node_id']
        issue = session.query(Issue).get(node_id=issue_node)
        # change and commit all attributes
        issue.labels.remove(add_get_label(body['label']))
        session.commit()


def issue_comment(action):
    # issue_comment: created, edited, deleted
    print(f'issue_comment event, {action} action')

    if action == 'created':
        issue_node = body['issue']['node_id']
        user_node = body['comment']['user']['node_id']
        issue_row = session.query(Issue).filter_by(node_id=issue_node).first()
        user_row = session.query(User).filter_by(node_id=user_node).first()

        # create Issue row and add to session
        issue_comment_row = IssueComment(issue=issue_row, user=user_row,
                                         body=body['comment']['body'],
                                         node_id=body['comment']['node_id'])
        session.add(issue_comment_row)
        session.commit()

    if action == 'edited':
        issue_comment_node = body['comment']['node_id']
        issue_comment = session.query(IssueComment).get(node_id=issue_comment_node)
        # change and commit all attributes
        issue_comment.body = body['comment']['body']
        session.commit()

    if action == 'deleted':
        issue_comment_node = body['comment']['node_id']
        issue_comment = session.query(IssueComment).filter_by(node_id=issue_comment_node).delete()
        session.commit()


def label(action):
    # label: created, edited, deleted
    print(f'label event, {action} action')

    if action == 'created':
        # create Issue row and add to session
        label_row = Label(name=body['label']['name'], description=None,
                          color=body['label']['color'], node_id=body['label']['node_id'])
        session.add(label_row)
        session.commit()

    if action == 'edited':
        label_node = body['label']['node_id']
        label = session.query(Label).get(node_id=label_node)
        # change and commit all attributes
        label.name = body['label']['name']
        label.color = body['label']['color']
        session.commit()

    if action == 'deleted':
        label_node = body['label']['node_id']
        label = session.query(Label).filter_by(node_id=label_node).delete()
        session.commit()
