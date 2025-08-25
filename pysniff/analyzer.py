import ast

from pysniff.rule_loader import MANAGER

def funny():
    pass
class Analyzer(ast.NodeVisitor):

    def __init__(self, rule_set, file_path):
        self.root_node = None
        self.issues = []
        self.rule_set = rule_set
        self.file_path = file_path
        self.rule_mgr = MANAGER
        self.user_defined_funcs = set()

    def visit_FunctionDef(self, node):
        self.generic_visit(node)


    def visit_Call(self, node):
        self._run_check(node, "Call", user_defined_funcs=self.user_defined_funcs)
        self.generic_visit(node)


    def visit_Import(self, node):
        self.generic_visit(node)


    def visit_ImportFrom(self, node):
        self.generic_visit(node)


    def visit_Constant(self, node):
        self.generic_visit(node)


    def visit_Name(self, node):
        self.generic_visit(node)


    def visit_Str(self, node):
        self.generic_visit(node)


    def visit_ExceptHandler(self, node):
        self.generic_visit(node)


    def run(self, code):
        self.root_node = ast.parse(code)
        self._get_user_func_names(self.root_node)

        self.visit(self.root_node)


    def _run_check(self, ast_node, check_type, **kwargs):
        """ Call the check function of each rule against the ast node

            :param ast_node: The ast node to check
            :param check_type: The type of check to perform
            :returns:
        """

        for rule in self.rule_mgr.rules_by_check_type[check_type]:
            if rule in self.rule_set:
                issue = rule.check(ast_node, **kwargs)

                if issue is not None:
                    issue.file_path = self.file_path
                    self.issues.append(issue)


    def _get_user_func_names(self, root_node):
        """ Collect names of user defined function in root_node.

        :param root_node: The ast node to collect functions from
        :returns:
        """

        for node in ast.walk(root_node):
            # collect user defined functions
            if isinstance(node, ast.FunctionDef):
                self.user_defined_funcs.add(node.name)
