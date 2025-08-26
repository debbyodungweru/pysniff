import sarif_om as om

from jschema_to_python.to_json import to_json


def get_report(manager, program_runtime):
    # add tool information

    rules = []
    if len(manager.rule_set) > 0:
        for rule in sorted(manager.rule_set, key=lambda r1: r1.id):
            r = om.ReportingDescriptor(
                id=rule.id,
                name=rule.name,
                message_strings=rule.message,
                full_description=rule.full_description,
                help_uri=rule.help_uri,
            )
            rules.append(r)

    tool = om.Tool(
        driver=om.ToolComponent(
            name="PySniff",
            version="1.0.0",
            information_uri="https://github.com/debbyodungweru/pysniff/",
            rules=rules,
        )
    )

    # add discovered code smells
    results = []
    for issue in manager.issues:
        result = om.Result(
            rule_id=issue.rule_id,
            message=om.Message(text=issue.message),
            locations=[
                om.Location(
                    physical_location=om.PhysicalLocation(
                        artifact_location=om.ArtifactLocation(uri=issue.file_path),
                        region=om.Region(start_line=issue.line, start_column=issue.column)
                    )
                )
            ]
        )
        results.append(result)

    # wrap everything in a Run obj
    run = om.Run(
        tool=tool,
        results=results
    )

    # build the top-level SARIF log
    sarif_log = om.SarifLog(
        version="2.1.0",
        schema_uri="https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        runs=[run]
    )

    sarif_json = to_json(sarif_log)

    return sarif_json

