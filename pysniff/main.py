import argparse
from pysniff import manager as pysniff_mgr

def main():
    """PySniff CLI"""

    # cli options setup
    parser = argparse.ArgumentParser(
        prog="pysniff",
        description="PySniff - a Python security code smell detector"
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
        help="specify rule IDs for analysis or skip to use all rules",
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

if __name__ == "__main__":
    main()