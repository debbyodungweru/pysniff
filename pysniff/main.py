import argparse

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
        default="vudenc",
        help="evaluate PySniff with a vulnerability dataset",
        choices=["vudenc"],
    )

    args = parser.parse_args()

    # print help if no target files provided
    if not args.files:
        parser.print_usage()

if __name__ == "__main__":
    main()