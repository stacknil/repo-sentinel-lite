# Public Readiness Review v0.1

## Executive Summary

Status: ready pending GitHub-side actions

No tracked secrets or real credentials were found in the repository contents
reviewed during this pass, and the most obvious public-facing hygiene issues
were addressed locally:

- `main` version metadata now aligns with `0.6.1`
- the release workflow now fails early if the pushed tag and package version
  disagree
- the committed `v0.6.1` handoff doc no longer embeds local absolute filesystem
  paths
- a minimal `SECURITY.md` now exists for future public reporting guidance

The repository is not blocked from public visibility by any confirmed secret
leak. The remaining concerns are mostly governance and release-process hygiene:
the `v0.6.1` release workflow failure is not rerunnable as-is, and the remaining
work is mostly GitHub-side configuration and presentation after a visibility
change.

## Findings

| area | finding | severity | recommended action | must-fix-before-public? |
| --- | --- | --- | --- | --- |
| secrets audit | No tracked secrets, tokens, or real credentials were found. Secret-like test fixtures under `tests/fixtures/sample_repo/` are placeholder-only and appear intentionally synthetic. | low | Keep fixture contents obviously fake and continue treating secret-like samples as test data only. | no |
| release workflow | Release run `23914337264` built `repo_sentinel_lite-0.6.0-*` from tag `v0.6.1` and failed with TestPyPI `HTTP 400`. This was a tag/version mismatch, not a permissions or network problem. | high | Do not rerun `23914337264`. Cut the next release from a commit whose tag and package version are intentionally aligned. | no |
| version hygiene | Before this pass, `main` still reported `0.6.0` even though the latest release/tag was `v0.6.1`. This is now corrected on `main`, but the historical `v0.6.1` tagged commit remains mismatched. | medium | Keep version bumps explicit before tagging, and let the workflow guard enforce this. | no |
| community docs | `LICENSE` and `SECURITY.md` now exist. `CONTRIBUTING.md` and `CODEOWNERS` are still absent, but neither looks mandatory for an initial public visibility flip. | low | Consider adding lightweight contributor guidance later if outside contributions become a goal. | no |
| release docs | `docs/release-handoff-v0.6.1.md` is maintainer-oriented and references a downstream consumer repo. The worst part, local absolute paths, was fixed in this pass, but the document is still internal-leaning. | low | Keep it if release artifacts are intentionally public, or move future handoff notes into a clearly maintenance-only area such as `docs/releases/`. | no |
| workflows and logs | Historical Actions logs reviewed for the failed release expose runner paths, artifact names, attestation output, and standard GitHub metadata, but no secret material was observed. | low | Acceptable to expose if the repo becomes public; no log scrubbing action identified from current evidence. | no |
| release workflow wording | `release.yml` previously described the workflow as intended for a private repo. This was misleading for a possible public future and was corrected in this pass. | low | Keep workflow comments neutral and repo-state-agnostic. | no |

## Release Workflow Failure Analysis

Run reviewed: `23914337264`

Classification: release ordering / version metadata mismatch

What happened:

- The release event fired for tag `v0.6.1`.
- The build job succeeded.
- The publish job attempted to upload `repo_sentinel_lite-0.6.0-py3-none-any.whl`
  to TestPyPI.
- TestPyPI returned `HTTP 400 Bad Request`.

Why it happened:

- The tagged commit `61f8efbf68e7b5d7d1e49ad20e491a065963a307` still declared package
  version `0.6.0` in both `pyproject.toml` and `src/repo_sentinel/__init__.py`.
- The release tag was `v0.6.1`, so the workflow published a `0.6.0` artifact
  under a `0.6.1` release context.
- TestPyPI rejected the upload because `0.6.0` had already been published.

What this is not:

- not a transient GitHub network issue
- not a Trusted Publishing permission failure
- not a missing release tag
- not an artifact download or upload-artifact failure

What was changed in this pass:

- `main` now reports package version `0.6.1`
- `.github/workflows/release.yml` now verifies that the release tag matches both
  version definition points before building distributions
- `RELEASE.md` now makes version bumping an explicit prerequisite

Rerun guidance:

- Do not rerun workflow run `23914337264`.
- A rerun would execute against the same historical tagged commit and would fail
  for the same reason.
- The correct next step is a future intentional release from a commit/tag pair
  that already agrees on version.

## Proposed Minimal Next Actions

1. Decide whether GitHub private vulnerability reporting will be enabled at the
   visibility flip; if not, replace the placeholder fallback-contact line in
   `SECURITY.md` first.
2. Decide whether maintainer handoff notes should remain in `docs/` or move into
   a more clearly internal maintenance location.
3. For the next release, bump version fields first, then create a new tag
   (likely `v0.6.2` rather than trying to repair `v0.6.1` in place), then run:

```bash
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z
gh release create vX.Y.Z --verify-tag
```

4. After the next successful release, confirm TestPyPI and release notes from a
   clean environment.

## Recommended Go-Public Checklist

1. Confirm the `SECURITY.md` reporting path is ready for public use:
   enable GitHub private vulnerability reporting, or replace the placeholder
   fallback-contact line first.
2. Re-read `README.md` as an outside visitor and confirm the opening still feels
   intentional after any visibility flip.
3. Confirm repository description, topics, and homepage in GitHub UI.
4. Review branch protection and rules after visibility change; the current
   private-repo API responses do not expose them.
5. Ensure the next planned release uses aligned tag/version metadata and the
   guarded release workflow.
6. Sanity-check the public docs tree for anything that is maintainer-only or too
   operationally specific.

## Recommended Post-Public Checklist

1. Enable or verify GitHub security features appropriate for a public repo
   (security advisories, private vulnerability reporting, dependency alerts).
2. Configure branch protection or rulesets on `main` if they are not already in
   place.
3. Consider adding `CONTRIBUTING.md` and lightweight issue / PR templates if you
   want outside contributions.
4. Revisit release automation after the first successful post-public release and
   confirm TestPyPI-only publishing still matches project intent.
5. Check the public Actions tab and release pages visually for presentation and
   clarity.

## What Should Remain Private or Be Cleaned First

No tracked secret material was identified that must be removed before a public
visibility change.

Items to keep non-public are the local-only workspace artifacts that already sit
outside version control, such as virtual environments, build outputs, caches,
and `%TEMP%` scratch content in the local checkout.

The main thing to settle before public visibility is GitHub-side governance
surface area, not secret leakage: specifically, decide the final reporting path
referenced by `SECURITY.md` and keep the next release intentionally
version-aligned.
