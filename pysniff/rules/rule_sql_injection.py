import ast

import pysniff
from pysniff.rules.base_rule import BaseRule


class RuleSQLInjection(BaseRule):
    check_types = ["Call", ]

    id = "PS003"
    name = "sql_injection"
    message = "Possible SQL injection via {}"
    full_description = ("Building SQL queries via string concatenation "
                        "or f-strings may allow SQL injection. "
                        "Use parameterized queries instead.")
    help_uri = "https://cwe.mitre.org/data/definitions/89.html"
    cwe = pysniff.CWE("89",
                      "Improper Neutralization of Special Elements used in an "
                      "SQL Command ('SQL Injection')")

    def check(self, node, context):

        # look for function call to cursor.execute()
        if isinstance(node.func, ast.Attribute) and node.func.attr == 'execute':

            # ensure the method is called on a cursor object
            if (isinstance(node.func.value, ast.Name) and
                node.func.value.id in self._get_sql_cursor_vars(context.get("root_node"))):

                if node.args:
                    execute_arg = node.args[0]
                    source = None
                    # check for string concatenation
                    if (isinstance(execute_arg, ast.BinOp) and
                            isinstance(execute_arg.op, ast.Add)):
                        source = "string concatenation"
                    # check for use of f-strings
                    elif isinstance(execute_arg, ast.JoinedStr):
                        source = "f-string"
                    # check for use of str.format()
                    elif (isinstance(execute_arg, ast.Call) and
                          isinstance(execute_arg.func, ast.Attribute) and
                          execute_arg.func.attr == "format"):
                        source = ".format()"

                    if source is not None:
                        return pysniff.Issue(
                            rule_id=self.id,
                            rule_name = self.name,
                            line=node.lineno,
                            column=node.col_offset,
                            message=self.message.format(source),
                            full_description=self.full_description,
                            help_uri=self.help_uri,
                            cwe=self.cwe,
                        )
        return None

    def _get_sql_cursor_vars(self, root_node):
        """ Collect SQL cursor assignment statements in root_node.

        :param root_node: The ast node to collect assignments from
        :returns:
        """
        cursor_vars = set()

        for node in ast.walk(root_node):
            # for any assignment statement whose value is a function call
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                # check if the called function is an attr of an obj, i.e. a method, called "cursor"
                if isinstance(node.value.func, ast.Attribute) and node.value.func.attr == "cursor":
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            cursor_vars.add(target.id)

        return cursor_vars