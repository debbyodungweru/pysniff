from pathlib import Path

from pysniff import rule_loader
from pysniff.analyzer import Analyzer


class PySniffManager:
    def __init__(self):
        """Initialize the PySniff manager

        :return:
        """
        self.file_list = []
        self.rule_set = set()
        self.output_format = "screen"
        self.excluded_files = []
        self.issues = []


    def load_files(self, files):
        """ Load target source files if they exist

        :param files: list of file and directory paths to load
        :return:
        """
        for file in files:
            path = Path(file)

            if path.exists():
                if path.is_dir():
                    self.file_list.extend([p for p in path.iterdir() if p.is_file()])
                else:
                    self.file_list.append(path)
            else:
                self.excluded_files.append((path, "No such file or directory"))


    def load_rules(self, rules):
        """ Load specified rules

        :param rules: list of rule IDs for analysis
        :return:
        """
        plugin_mgr = rule_loader.MANAGER

        # default to all rules if none specified
        if rules is None:
            self.rule_set = set(plugin_mgr.rules)
        else:
            for r in rules:
                rule = plugin_mgr.rules_by_id.get(r)
                if rule is not None:
                    self.rule_set.add(rule)


    def run_analysis(self):
        """ Begin analysis on target source code using specified rules

        :return:
        """
        excluded = []

        for file in self.file_list:
            # get absolute file path
            file_path = str(file.resolve())

            with open(file, "r") as f:
                try:
                    self.parse_ast(f.read(), file_path)
                except (PermissionError, SyntaxError, UnicodeDecodeError) as e:
                    excluded.append((file, f"Unable to read file: {e}"))

        # remove unparsable files from file_list
        for excl in excluded:
            self.file_list.remove(excl[0])


    def parse_ast(self, code, file_path, rule_set = None, dataset_name = None):
        """ Begin parsing the code with ast

            :param code: The source code to parse
            :param file_path: The path to the file to parse
            :param rule_set: Alternative rule set to use for analysis
            :param dataset_name: name of dataset that file belongs to, in evaluation mode
            :returns:
        """
        rule_set = rule_set or self.rule_set

        analyzer = Analyzer(rule_set, file_path, dataset_name)
        analyzer.run(code)

        self.issues.extend(analyzer.issues)

