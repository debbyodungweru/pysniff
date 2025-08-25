import ast

import pysniff
from pysniff.rules.base_rule import BaseRule


class RuleEval(BaseRule):

    check_types = ["Call",]

    id = "PS001"
    name = "eval_used"
    message = "Use of eval() detected"
    full_description = "Avoid exec(), it exposes programs to code injection and makes code harder to maintain."
    help_uri = "https://cwe.mitre.org/data/definitions/78.html"
    cwe = pysniff.CWE("78",
                      "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')")


    def check(self, node, **kwargs):
        # Look for function call to eval()
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "eval":

            # exclude user defined functions
            user_funcs = kwargs.get("user_defined_funcs")
            if user_funcs is not None and "eval" in user_funcs:
                return None

            else:
                return pysniff.Issue(
                    rule_id=self.id,
                    rule_name=self.name,
                    line=node.lineno,
                    column=node.col_offset,
                    message=self.message,
                    full_description = self.full_description,
                    help_uri=self.help_uri,
                    cwe=self.cwe,
                )
        return None
