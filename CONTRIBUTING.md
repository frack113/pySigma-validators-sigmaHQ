# Contributing

## How to update the validator data

The validators rely on the JSON files located in the `tools/` directory.

- `sigmahq_taxonomy.json` - Sigma taxonomy data
- `sigmahq_filename.json` - Sigma rule filename prefix patterns
- `sigmahq_windows_eventid.json` - Windows event ID categories
- `sigmahq_windows_provider.json` - Windows provider names

These files are validated against JSON schemas in `json-schema/`. After updating any JSON file, run the schema validation:

```bash
poetry run check-jsonschema --schemafile ./json-schema/schema_sigmahq_taxonomy.json ./tools/sigmahq_taxonomy.json
poetry run check-jsonschema --schemafile ./json-schema/schema_sigmahq_filename.json ./tools/sigmahq_filename.json
poetry run check-jsonschema --schemafile ./json-schema/schema_sigmahq_windows_eventid.json ./tools/sigmahq_windows_eventid.json
poetry run check-jsonschema --schemafile ./json-schema/schema_sigmahq_windows_provider.json ./tools/sigmahq_windows_provider.json
```
