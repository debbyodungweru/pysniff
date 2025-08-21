class Issue:

    def __init__(self, rule_id, line, column, message, help_uri):
        self.rule_id = rule_id
        self.line = line
        self.column = column
        self.message = message
        self.help_uri = help_uri
