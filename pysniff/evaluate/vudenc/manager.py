import json
import os
import time
from pathlib import Path
from collections import defaultdict

class VudencManager:
    def __init__(self, pysniff_mgr):
        """ Initializes the VUDENC dataset manager

        :param pysniff_mgr: PySniff manager object that contains global app data
        """
        self.pysniff_mgr = pysniff_mgr
        self.dataset = {}

        self.exclusions = set()

        self.dataset_files = ["plain_sql.json", "plain_remote_code_execution.json"]

        self.rule_dataset = {
            "PS001" : self.dataset_files[1],
            "PS002" : self.dataset_files[1],
            "PS003" : self.dataset_files[0],
            "PS004" : self.dataset_files[0],
        }

        self.repository_count = {}
        self.file_count = {}

        self.result = {}

    def load_datasets(self):
        """ Loads processed datasets from json files. """
        dataset_dir = os.path.join(os.path.dirname(__file__), "processed_datasets")
        path = Path(dataset_dir)

        if path.exists() and path.is_dir():
            for p in path.iterdir():
                if p.is_file():
                    with open(p, "r", encoding="utf-8") as json_file:
                        json_data = json.loads(json_file.read())
                    self.dataset[p.name] = json_data


        return self.dataset is not None

    def run_analysis(self):
        """ Runs static analysis on VUDENC dataset. """

        self.result["summary"] = {}

        start = time.perf_counter()

        # for each rule, get the dataset file(s) to be evaluated
        for rule in self.pysniff_mgr.rule_set:
            self.result[rule.id] = {}

            repos = set()
            files = set()
            excluded = 0

            dataset_name = self.rule_dataset[rule.id]
            for file_data in self.dataset[dataset_name]:
                if file_data["source"] is not None:
                    full_path = file_data["html_url"] + file_data["file_path"]
                    try:
                        self.pysniff_mgr.parse_ast(file_data["source"], full_path, {rule}, file_data["dataset"])
                        repos.add(file_data["html_url"][:file_data["html_url"].rfind("/")])
                        files.add(full_path)
                    except (PermissionError, SyntaxError, UnicodeDecodeError) as e:
                        self.exclusions.add(full_path)
                        excluded += 1

            self.result[rule.id]["repos_scanned"] = len(repos)
            self.result[rule.id]["files_scanned"] = len(files)
            self.result[rule.id]["unparsable_files"] = excluded

        end = time.perf_counter()
        self.result["summary"]["program_runtime"] = f"{(end - start):4f}s"

        return self._evaluate_results()

    def _evaluate_results(self):
        """" Evaluates analysis results. """

        # get issues by rule
        grouped_issues = _group_issues_by_rule(self.pysniff_mgr.issues)

        for rule_id, issues_for_rule in grouped_issues.items():
            self.result[rule_id]["issues_found"] = len(issues_for_rule)
            self.result[rule_id]["issues"] = []
            for i in issues_for_rule:
                self.result[rule_id]["issues"].append(f"{i.file_path}:{i.line}")

        self.result["summary"]["active_rules"] = len(self.pysniff_mgr.rule_set)
        self.result["summary"]["issues_found"] = len(self.pysniff_mgr.issues)

        return self.result


def _group_issues_by_rule(issues):
    grouped = defaultdict(list)
    for issue in issues:
        grouped[issue.rule_id].append(issue)
    return dict(grouped)
