import argparse
import sys
import textwrap
import time
from pprint import pp

from pysniff import manager as pysniff_mgr
from pysniff import rule_loader
from pysniff import report
from pysniff.evaluate.vudenc.manager import VudencManager


def main():
    """PySniff CLI"""

    # cli options setup
    parser = argparse.ArgumentParser(
        prog="pysniff",
        description="PySniff - a Python security code smell detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "files",
        metavar="files",
        type=str,
        nargs="*",
        help="""The file(s) or directory(s) to sniff"""
    )

    parser.add_argument(
        "-f", "--format",
        dest="output_format",
        type=str,
        default="screen",
        help="specify output format",
        choices=["screen", "json", "sarif"],
    )

    parser.add_argument(
        "-r", "--rules",
        dest="rules",
        type=str,
        help="specify comma-separated rule IDs for analysis or skip to use all rules",
        default=None,
    )

    parser.add_argument(
        "-o", "--output",
        dest="output_file",
        nargs="?",
        help="specify file to write output to",
        default=None,
    )

    parser.add_argument(
        "--evaluate",
        dest="evaluate",
        default=None,
        help="evaluate PySniff with a vulnerability dataset",
        choices=["vudenc"],
    )

    # load and initialize rules as plugins
    plugin_mgr = rule_loader.MANAGER

    plugin_info = [f"{p.id}\t{p.name}" for p in plugin_mgr.rules]
    plugin_info = "\n\t".join(sorted(plugin_info))

    epilog_text = textwrap.dedent(
        """
            Available rules:
        """
    ) + "\t" + plugin_info

    parser.epilog = epilog_text

    # measure program runtime
    start = time.perf_counter()

    args = parser.parse_args()

    # print help if no target file or evaluation args provided
    if len(args.files) == 0 and not args.evaluate:
        parser.print_usage()
        print()
        sys.exit(0)

    # initialize manager obj
    manager = pysniff_mgr.PySniffManager()

    # load specified rules
    manager.load_rules(args.rules.split(",") if args.rules is not None else None)

    if len(manager.rule_set) == 0:
        if args.rules:
            for r in args.rules.split(","):
                print("Rule not found: " + r)
        print("Could not load rules")
        print("exiting...")
        sys.exit(1)

    # for regular scanning
    if not args.evaluate:
        # initialize target files
        manager.load_files(args.files)

        # analyze target files
        manager.run_analysis()

        # measure program runtime
        end = time.perf_counter()
        program_runtime = end - start

        # prepare and display report
        report.generate_report(manager, args.output_format, args.output_file, program_runtime)

    # for PySniff evaluation
    else:
        evaluation_mgr = None

        # evaluate with specified datasets
        if args.evaluate == "vudenc":
            evaluation_mgr = VudencManager(manager)
        else:
            print(f"Unknown dataset: {args.evaluate}")
            print("exiting...")
            sys.exit(1)

        print("Loading dataset...")
        if evaluation_mgr.load_datasets():
            print("Done loading.")
        else:
            print("Could not load dataset")
            print("exiting...")
            sys.exit(1)

        print("Starting evaluation...")
        evaluation_results = evaluation_mgr.run_analysis()
        print("Done evaluating.\n")

        pp(evaluation_results, indent=2)

if __name__ == "__main__":
    main()