import os
import importlib
import inspect
from pysniff.rules.base_rule import BaseRule

class RuleManager:
    def __init__(self):
        self.rules = []
        self.rules_by_id = {}
        self.rules_by_check_type = {}
        self.load_rules()

    def load_rules(self):
        rules = []
        rules_dir = os.path.join(os.path.dirname(__file__), "rules")

        for file in os.listdir(rules_dir):
            if file.startswith("rule_") and file.endswith(".py"):
                module_name = f"pysniff.rules.{file[:-3]}"
                module = importlib.import_module(module_name)

                # Find classes in module that subclass BaseRule
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if issubclass(obj, BaseRule) and obj is not BaseRule:
                        rules.append(obj())  # instantiate rule
        self.rules = rules
        self.rules_by_id = {r.id: r for r in self.rules}

        self.rules_by_check_type = {}
        for r in self.rules:
            for c in r.check_types:
                self.rules_by_check_type.setdefault(c, []).append(r)


MANAGER = RuleManager()