class GitkanbanException(Exception):
    """ any exception from Gitkanban """
    def __init__(self, msg):
        super(GitkanbanException, self).__init__(msg)
        self.msg = msg
    pass

class InvalidFileTypeException(GitkanbanException):
    """ when conf file extension is not expected """
    pass

class GithubAPIException(GitkanbanException):
    """when github server error occurs"""
    pass

class NoDataFoundException(GitkanbanException):
    pass
