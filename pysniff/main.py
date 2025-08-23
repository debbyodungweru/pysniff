import argparse
import sys
import textwrap

from pysniff import manager as pysniff_mgr
from pysniff import rule_loader


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
        choices=["json", "sarif"],
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
        type=argparse.FileType("w", encoding="utf-8"),
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
    args = parser.parse_args()

    # print help if no target file or evaluation args provided
    if not args.files and not args.evaluate:
        parser.print_usage()

    # initialize manager obj
    manager = pysniff_mgr.PySniffManager()

    if not args.evaluate:
        # initialize target files
        manager.load_files(args.files)
    else:
        # evaluate with specified dataset
        pass

    # load specified rules
    manager.load_rules(args.rules.split(",") if args.rules is not None else None)

    if len(manager.rule_set) == 0:
        if args.rules:
            for r in args.rules.split(","):
                print("Rule not found: " + r)
        print("Could not load rules")
        print("exiting...")
        sys.exit(1)


if __name__ == "__main__":
    main()