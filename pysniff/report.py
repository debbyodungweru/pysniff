import pysniff.report_formatters.screen as screen
import pysniff.report_formatters.sarif as sarif


def generate_report(manager, output_format="screen", output_file=None, program_runtime=0):
    """ Display PySniff report in the selected output format, in the CLI or written to the specified output file.

    :param manager: PySniff manager
    :param output_format: output format (screen, JSON or SARIF) defaults to screen
    :param output_file: optional output file to write to
    :param program_runtime: total program runtime in seconds, defaults to 0
    :return:
    """

    report = ""
    if output_format == "json":
        pass
    elif output_format == "sarif":
        report = sarif.get_report(manager, program_runtime)
    else:
        report = screen.get_report(manager, program_runtime)


    # write the report to the output file if specified
    if output_file:
        with open(output_file, "w") as f:
            f.write(report)

        print(f"PySniff report written to file\n\t-> {output_file}")

    # display the report on the screen
    else:
        print(report)
