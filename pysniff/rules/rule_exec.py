import ast

import pysniff
from pysniff.rules.base_rule import BaseRule


class RuleExec(BaseRule):
    check_types = ["Call", ]

    id = "PS002"
    name = "exec_used"
    message = "Use of exec() detected"
    full_description = "Use of exec() gives attackers a back door into a program's runtime."
    help_uri = "https://cwe.mitre.org/data/definitions/78.html"
    cwe = pysniff.CWE("78",
                      "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')")

    def check(self, node, context):
        # Look for function call to exec()
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "exec":

            # exclude user defined functions
            user_funcs = context.get("user_defined_funcs")
            if user_funcs is not None and "exec" in user_funcs:
                return None

            else:
                return pysniff.Issue(
                    rule_id=self.id,
                    rule_name = self.name,
                    line=node.lineno,
                    column=node.col_offset,
                    message=self.message,
                    full_description=self.full_description,
                    help_uri=self.help_uri,
                    cwe=self.cwe,
                )
        return None
