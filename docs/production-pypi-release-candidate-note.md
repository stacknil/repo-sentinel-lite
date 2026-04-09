# Production PyPI Release Candidate Note

`0.6.2` is the recommended first stable production candidate because the real
TestPyPI smoke already succeeded for `0.6.2rc1`, making `0.6.2` the cleanest
promotion target with no evidence that a version skip is necessary. Repository
metadata is now prepared at `0.6.2`.

What `0.6.2rc1` already proved on TestPyPI:

- the package builds correctly
- the GitHub Actions release workflow can build first and publish second
- Trusted Publishing works end to end for this repository
- the published package installs successfully in a clean Python 3.14
  environment
- both `repo-sentinel --help` and `python -m repo_sentinel --help` work after
  install

What still must be manually verified before a real production publish:

- whether production PyPI already has a matching Trusted Publisher or pending
  publisher configured
- whether the GitHub environment name `pypi` matches the PyPI configuration
- whether the first stable publish will also create the production project
  `repo-sentinel-lite`
- that the maintainer releases from the prepared `0.6.2` commit and tags
  `v0.6.2`
