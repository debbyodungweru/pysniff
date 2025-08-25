import pysniff


class BaseRule:

    check_types = []

    id = "PS000"
    name = ""
    message = ""
    full_description = ""
    help_uri = ""
    cwe = pysniff.CWE("", "")


    def check(self, node, context):
        """ Main rule logic

        :param node: ast node to check
        :param context: dictionary with contextual information
        :returns: pysniff.issue.Issue
        """
        return None
