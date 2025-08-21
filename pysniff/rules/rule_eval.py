import ast

import pysniff
from pysniff.rules.base_rule import BaseRule


class RuleEval(BaseRule):

    id = "PS001"
    name = "eval_used"
    message = "Use of eval() detected"
    help_uri = "https://owasp.org/www-community/attacks/Code_Injection"


    def check(self, node):
        # Look for function call to eval()
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "eval":
            return pysniff.Issue(
                rule_id=self.id,
                line=node.lineno,
                column=node.col_offset,
                message=self.message,
                help_uri=self.help_uri,
            )
        return None
