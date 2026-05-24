# Leakwatch VS Code Extension

Detect leaked secrets directly in your editor with real-time diagnostics.

## Features

- **Scan on Save** — automatically scans files when you save (configurable)
- **Workspace Scanning** — scan the entire workspace with one command
- **Problems Panel** — findings appear as diagnostics with severity levels
- **Status Bar** — shows scan status and finding count at a glance

## Requirements

- [Leakwatch CLI](https://github.com/HodeTech/Leakwatch) must be installed and available in your `PATH`
- Install via: `go install github.com/HodeTech/leakwatch@latest` or `brew install leakwatch`

## Commands

| Command | Description |
|---------|-------------|
| `Leakwatch: Scan Workspace` | Scan all files in the workspace |
| `Leakwatch: Scan Current File` | Scan only the active file |
| `Leakwatch: Clear Diagnostics` | Clear all Leakwatch diagnostics |

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `leakwatch.executablePath` | `leakwatch` | Path to the leakwatch binary |
| `leakwatch.scanOnSave` | `true` | Automatically scan files on save |
| `leakwatch.minSeverity` | `low` | Minimum severity to report |
| `leakwatch.showInlineHints` | `true` | Show inline hints for detected secrets |
| `leakwatch.customRulesPath` | `""` | Path to custom rules YAML file |

## Severity Mapping

| Leakwatch Severity | VS Code Diagnostic |
|--------------------|-------------------|
| Critical | Error |
| High | Error |
| Medium | Warning |
| Low | Information |

## Development

```bash
cd vscode
npm install
npm run watch    # development mode with auto-rebuild
# Press F5 in VS Code to launch Extension Development Host
```

## Building

```bash
npm run compile                      # build for production
npx @vscode/vsce package             # create .vsix package
```

## License

MIT — see [LICENSE](../LICENSE) for details.
