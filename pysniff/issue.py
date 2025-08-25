class Issue:

    def __init__(self, rule_id, rule_name, line, column, message, full_description, help_uri, cwe):
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.file_path = ""
        self.line = line
        self.column = column
        self.message = message
        self.full_description = full_description
        self.help_uri = help_uri
        self.cwe = cwe

    def __str__(self):
        return f"""Issue{{
    rule={self.rule_id}({self.rule_name}),
    file_path={self.file_path},
    line={self.line},
    column={self.column},
    message={self.message},
    full_description={self.full_description},
    help_uri={self.help_uri},
    cwe=CWE-{self.cwe.id}
}}"""


class CWE:
    def __init__(self, id, name):
        self.id = id
        self.name = name
