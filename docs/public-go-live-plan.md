# Public Go-Live Plan

## Minimal Change Sequence

1. Commit and push the current public-readiness pass, including `SECURITY.md`,
   the audit note, and the release-hygiene fixes.
2. Confirm `main` is green, the working tree is clean, and the public-readiness
   findings in `docs/public-readiness-v0.1.md` are still accurate.
3. Confirm the next intended release path is version-aligned:
   update version fields first, then `git tag`, then `git push origin <tag>`,
   then `gh release create --verify-tag`.
4. Decide the final reporting path referenced by `SECURITY.md`:
   enable GitHub private vulnerability reporting at the visibility flip, or
   replace the placeholder fallback contact first.
5. Prepare GitHub-side settings that should exist immediately after the
   visibility flip:
   branch protection or rulesets for `main`, repository description, topics,
   and any security settings you want enabled on day one.
6. Change repository visibility from private to public in GitHub UI during a
   low-activity window.
7. Immediately verify the public landing surface:
   README, LICENSE, releases, Actions tab, default branch, and issue links.
8. Immediately apply or confirm `main` branch protection and rulesets after the
   visibility change if they were not already active.

## Rollback Plan

1. If a blocker is found before the visibility change, stop and fix it in
   private; do not proceed with the flip.
2. If a blocker is found immediately after the visibility change, switch the
   repository back to private in GitHub UI first.
3. If the blocker involves accidentally exposed sensitive material, rotate the
   affected credential or token first, then clean the repository and logs as a
   separate incident response task.
4. If the blocker is presentation or governance only, revert or patch the
   affected docs or workflow files on `main`, then reassess public readiness.
5. Do not rewrite history as part of a same-minute rollback unless incident
   response clearly requires it; prefer visibility reversal, credential
   rotation, and a normal forward fix.
