# Symlink Policy

`repo-sentinel-lite` uses a no-follow policy by default. It never reads a file
through a file symlink or a symlinked directory, even when the resolved target
would remain inside the requested repository root.

This is a traversal safety boundary, not a filesystem sandbox. The scanner
still trusts the operating system for ordinary non-symlink file reads and does
not inspect Git history.

## Behavior matrix

| Entry | Full scan | Changed-file scan | Coverage |
| --- | --- | --- | --- |
| Regular file | Inspect content | Inspect when selected | File counters |
| In-root file symlink | Check link name; skip target | Check link name; skip target | `skipped_files` |
| Outside-root file symlink | Check link name; skip target | Check link name; skip target | `skipped_files` |
| Directory symlink | Check link name; prune before descent | Skip a selected file below the link | `skipped_directories`; selected file also enters `skipped_files` |
| Directory symlink loop | Check link name; prune before descent | Skip without resolving the loop | `skipped_directories` |

There is no implicit or explicit follow mode. A repository that intentionally
uses symlinks must scan the canonical target path separately if that content
should be inspected.

## Name classification

Suspicious-filename checks apply to the symlink's repository-relative link
name. They never apply to the target name, and no detector receives target
content through the link.

For a changed file below a directory symlink, coverage records both the
directory link that blocked traversal and the requested file candidate that
was not inspected. Repeated changed paths through the same directory link do
not duplicate the directory diagnostic.

## Coverage and exit status

Skipped file links use the existing `symlink_policy` reason in
`coverage.skipped_files`. Pruned directory links add these optional fields:

```json
{
  "coverage": {
    "directories_skipped": 1,
    "skipped_directories": [
      {"path": "linked-dir", "reason": "symlink_policy"}
    ]
  }
}
```

The example is partial; normal reports retain the file coverage fields.
Directory counts are separate so `files_considered` remains a file-only
denominator. All paths are normalized repository-relative paths, and no target
path, target content, operating-system error, or repository-root path is
included.

Coverage is informational. Baselines preserve it, and
`--fail-on-findings` / `--fail-on-severity` continue to evaluate findings only.

## Compatibility impact

- Full scans now surface pruned directory links instead of omitting their
  traversal decision from coverage.
- Changed-file scans no longer inspect a file through an in-root directory
  symlink.
- An outside-root file symlink selected in changed-file mode now produces the
  same link-name finding and coverage as a full scan instead of disappearing.
- File-only coverage and no-skip output retain their previous shape.

Symlink tests use synthetic targets. Linux CI exercises normal symlink
behavior; Windows tests skip only when the environment cannot create the
required link type.
