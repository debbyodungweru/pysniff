import pysniff


class BaseRule:

    check_types = []

    id = "PS000"
    name = ""
    message = ""
    full_description = ""
    help_uri = ""
    cwe = pysniff.CWE("", "")


    def check(self, node, **kwargs):
        """ Main rule logic

        :param node: ast node to check
        :param kwargs: additional keyword arguments
        :returns: pysniff.issue.Issue
        """
        return None
