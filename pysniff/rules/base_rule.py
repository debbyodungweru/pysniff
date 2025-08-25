import pysniff


class BaseRule:

    check_types = []

    id = "PS000"
    name = ""
    message = ""
    full_description = ""
    help_uri = ""
    cwe = pysniff.CWE("", "")


    def check(self, node):
        """ Main rule logic

        :param node: ast node to check
        :returns: pysniff.issue.Issue
        """
        return None
