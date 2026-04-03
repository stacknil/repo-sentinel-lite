# Public Go-Live Checklist

## Pre-Flip Checks

1. Confirm the latest public-readiness commit is present on `origin/main`.
2. Review recent Actions history and logs for anything that should not become
   publicly visible.
3. Review the Releases and Tags pages as an outside viewer would see them.
4. Decide the fallback contact for `SECURITY.md` if GitHub private
   vulnerability reporting will not be enabled.

## Visibility Flip

1. Change the repository from private to public in GitHub UI.

## Immediate Post-Flip Actions

1. Enable GitHub private vulnerability reporting if available.
2. Configure branch protection or rulesets for `main`.
3. Set required status checks for `main` if branch protection is available.
4. Review repository description, homepage, and topics in the sidebar.
5. Verify that `README`, `LICENSE`, and `SECURITY` render clearly in the public
   repository view.

## Final Validation

1. Verify the repository is publicly viewable as intended.
2. Verify releases and tags are visible and make sense to an outside viewer.
3. Verify no unexpected public logs or artifacts are exposed in Actions.

## Rollback Note

1. If unexpected exposure is discovered, stop and assess whether repository
   visibility should be reverted after documenting what was exposed.
