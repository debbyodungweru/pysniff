import os
import importlib
import inspect
from pysniff.rules.base_rule import BaseRule

class RuleManager:
    def __init__(self):
        self.rules = None
        self.load_rules()

    def load_rules(self):
        rules = []
        rules_dir = os.path.join(os.path.dirname(__file__), "rules")

        for file in os.listdir(rules_dir):
            if file.startswith("rule_") and file.endswith(".py"):
                module_name = f"rules.{file[:-3]}"
                module = importlib.import_module(module_name)

                # Find classes in module that subclass BaseRule
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if issubclass(obj, BaseRule) and obj is not BaseRule:
                        rules.append(obj())  # instantiate rule
        self.rules = rules

MANAGER = RuleManager()