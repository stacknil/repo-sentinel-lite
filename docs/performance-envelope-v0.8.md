# v0.8 Performance Envelope

This is a local synthetic benchmark for the v0.8 rule and baseline semantics
work. It is a reproducibility note, not a cross-machine performance claim.

Command:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\benchmark-performance-envelope.ps1
```

Fixture shape:

- synthetic repository with `README.md`, `LICENSE`, and `.gitignore`
- `src/file-*.txt` text files with one non-secret line each
- full scan writes JSON output
- changed-files scan checks 50 listed files and still runs required-file checks

Observed result:

| Files | Full scan seconds | Changed files | Changed-files scan seconds |
| ---: | ---: | ---: | ---: |
| 1,000 | 0.873 | 50 | 0.278 |
| 10,000 | 5.478 | 50 | 0.247 |

Interpretation:

- Full scans scale with repository file count because traversal and text
  classification inspect each eligible file.
- Changed-files mode is useful when an integration already has a trusted file
  list, such as a custom pre-commit wrapper.
- The built-in provider still scans the repository root to preserve coverage
  for existing consumers.
