class BaseRule:
    id = "PS000"
    name = ""
    message = ""
    help_uri = ""

    def check(self, node):
        """Main rule logic
        :returns: pysniff.issue.Issue
        """
        return None
