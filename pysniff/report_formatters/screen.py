def get_report(manager, program_runtime):
    """ Get the scan report in plain text format """

    lines = []

    lines.append(format_heading("PySniff Security Scan Report"))

    lines.append(included_files(manager.file_list))
    lines.append(excluded_files(manager.excluded_files))
    lines.append(active_rules(manager.rule_set))

    lines.append(format_heading("Code Smells Discovered", level=2))
    lines.append(issues_found(manager.issues))

    lines.append(format_heading("Scan Summary", level=2))
    lines.append(scan_summary(len(manager.file_list), len(manager.rule_set), len(manager.issues), program_runtime))

    lines.append(format_heading("End of Report — PySniff", level=1))

    return "\n".join([line for line in lines])


def format_heading(text, level=1):
    """ Format heading text

    :param text: text to be formatted
    :param level: level of formatting, 1 = main heading, 2 = subheading.
    :return: formatted text"""

    separator = "=" if level == 1 else "-"

    return f"\n{separator*75}\n\t{text}\n{separator*75}"


def included_files(file_list):
    lines = ["\nScanned Files:"]

    if len(file_list) > 0:
        for file in file_list:
            lines.append(f"\t+ {file}")

    else:
        lines.append("\t- No files")

    return "\n".join([line for line in lines])


def excluded_files(file_list):
    lines = ["\nSkipped Files:"]

    if len(file_list) > 0:
        for file, reason in file_list:
            lines.append(f"\t- {file} ({reason})")

    else:
        lines.append("\t- No files")

    return "\n".join([line for line in lines])


def active_rules(rule_set):
    lines = ["\nActive Rules:"]

    if len(rule_set) > 0:
        for rule in sorted(rule_set, key=lambda r: r.id):
            lines.append(f"\t+ {rule.id} {rule.name}")

    else:
        lines.append("\t- No rules selected")

    return "\n".join([line for line in lines])


def issues_found(issues_list):
    lines = []

    if len(issues_list) == 0:
        lines.append("\t- No code smells found")
    else:
        for issue in issues_list:
            lines.append(f"[{issue.rule_id}] {issue.message}")
            lines.append(f"\t-> {issue.file_path}:{issue.line}")
            lines.append(f"\tCWE: CWE-{issue.cwe.id}: {issue.cwe.name}")
            lines.append(f"\tSuggestion: {issue.full_description}")
            lines.append(f"\tMore info: {issue.help_uri}\n")

    return "\n".join([line for line in lines])


def scan_summary(file_count, rule_count, issue_count, program_runtime):
    lines = []

    lines.append(f"\nTotal files scanned\t\t:  {file_count}")
    lines.append(f"Rules applied\t\t\t:  {rule_count}")
    lines.append(f"Code smells discovered\t\t:  {issue_count}")
    lines.append(f"Scan time\t\t\t:  {program_runtime:4f}s")

    return "\n".join([line for line in lines])
