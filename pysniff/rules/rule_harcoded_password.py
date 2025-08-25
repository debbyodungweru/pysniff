import ast
import re

import pysniff
from pysniff.rules.base_rule import BaseRule


class RuleHardcodedPassword(BaseRule):
    check_types = ["Assign", "FunctionDef", "Call", "Compare"]

    id = "PS004"
    name = "hardcoded_password"
    message = "Possible hardcoded password"
    full_description = "Hardcoding passwords or secrets in source code makes them easily discoverable. Use environment variables or secret managers instead."
    help_uri = "https://cwe.mitre.org/data/definitions/798.html"
    cwe = pysniff.CWE("798",
                      "Use of Hard-coded Credentials")

    suspicious_names = re.compile(r"(pw|pwd|pass|passwd|password|secret|token|key)", re.IGNORECASE)


    def check(self, node, context):

        # check regular variable assignment statements
        if isinstance(node, ast.Assign):
            # check dictionary attributes
            if isinstance(node.value, ast.Dict):
                for key, val in zip(node.value.keys, node.value.values):
                    if isinstance(key, ast.Constant) and isinstance(key.value, str):
                        if self.suspicious_names.search(key.value):
                            if isinstance(val, ast.Constant) and isinstance(val.value, str):
                                return self.get_issue(node)

            for target in node.targets:
                # check both simple assignments (pw="secret") and attribute assignments (self.pw="secret")
                if ((isinstance(target, ast.Name) and self.suspicious_names.search(target.id)) or
                    (isinstance(target, ast.Attribute) and self.suspicious_names.search(target.attr))):
                    # ensure that the assignment value is a string
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        return self.get_issue(node)

        # check function parameter default values
        elif isinstance(node, ast.FunctionDef):
            # ensure the indexes of param names correspond to that of the default values
            for arg, default in zip(node.args.args[::-1], node.args.defaults[::-1]):
                # ensure that the default value is a str
                if isinstance(default, ast.Constant) and isinstance(default.value, str):
                    # check the param name
                    if self.suspicious_names.search(arg.arg):
                        return self.get_issue(node)

        # check function call keyword args
        elif isinstance(node, ast.Call):
            for kw in node.keywords:
                if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    if self.suspicious_names.search(kw.arg or ""):
                        return self.get_issue(node)

        # check str values used in comparison against password-like variables
        elif isinstance(node, ast.Compare):
            for comparator in node.comparators:
                # ensure value is a str
                if isinstance(comparator, ast.Constant) and isinstance(comparator.value, str):
                    if isinstance(node.left, ast.Name):
                        if self.suspicious_names.search(node.left.id):
                            return self.get_issue(node)

        return None


    def get_issue(self, node):
        return pysniff.Issue(
            rule_id=self.id,
            rule_name=self.name,
            line=node.lineno,
            column=node.col_offset,
            message=self.message,
            full_description=self.full_description,
            help_uri=self.help_uri,
            cwe=self.cwe,
        )
