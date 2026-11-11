# GitHub and release guide

Use `README.md` as the landing page and `VERIFICATION.md` for what was actually
checked. Detailed setup, method and history live under `docs/`. The package is
v0.2.1; the included headline study was collected with v0.2.0.

## Before a commit

From the repository root, stage the intended files and run the same local checks
used by CI:

```sh
git add .
python scripts/check_repository.py
python -m unittest discover -s tests -v
git diff --cached --check
git diff --cached --stat
```

The repository checker validates relative documentation/report links, frozen
evidence hashes and tracked-file hygiene. Its key/token/path checks are bounded
sanity checks, not a comprehensive secret scanner. Local runs, caches, captures,
private keys, build outputs and editor settings are ignored. Reviewed synthetic
examples are intentionally tracked.

## First push

Create an empty GitHub repository. Replace `YOUR_REPOSITORY_URL` with its SSH or
HTTPS clone URL. Run `git init -b main` only if Git is not already initialized.

```sh
git init -b main
git add .
git commit -m "Prepare BeaconLab v0.2.1 for GitHub"
git remote add origin YOUR_REPOSITORY_URL
git push -u origin main
```

Suggested repository name: `beacon-lab`.
Suggested description: `A reproducible Python lab for evaluating periodicity-based detection on synthetic HTTP/HTTPS traffic.`
Suggested topics: `python`, `network-security`, `detection-engineering`, `traffic-analysis`, `cybersecurity`, `research`, `http`, `tls`.

The CI workflow runs on pushes and pull requests, using Linux with Python 3.10,
3.12 and 3.14. It checks repository hygiene, executes the test suite and verifies
the installed CLI. Action dependencies are pinned to reviewed commits and the
workflow token has read-only repository permissions. CI is configured here;
its first GitHub execution still needs to pass after push.

## Create a source release

```sh
python scripts/package_release.py --output dist
```

The script uses the Git index file list in a checkout and a reviewed source-tree
allowlist in an extracted archive. It checks the repository before packaging,
excludes Git metadata/local outputs, and creates a versioned ZIP in ignored
`dist/`. The ZIP includes a generated `RELEASE_SHA256.json` for its exact files;
that manifest excludes itself. A companion `.sha256` hashes the ZIP.

The generated checksum manifest is archive metadata, not a maintained repository
file. `examples/**` has line-ending conversion disabled so frozen evidence keeps
its original bytes across checkouts. Keep reports and their figures together.

## Evidence changes

A documentation fix should not regenerate old observations or change a frozen
model. A new detector experiment needs a new protocol/configuration and fresh
held-out collection. Review every new example before adding it to Git, document
its provenance in `examples/README.md`, and keep integrations unvalidated until
they have actually been exercised.

## Workflow references

- [GitHub: building and testing Python](https://docs.github.com/en/actions/tutorials/build-and-test-code/python)
- [GitHub: secure workflow use](https://docs.github.com/en/actions/reference/security/secure-use)
- [Pinned checkout release](https://github.com/actions/checkout/commit/3d3c42e5aac5ba805825da76410c181273ba90b1)
- [Pinned setup-python release](https://github.com/actions/setup-python/commit/6d4fd22b20465ccc0f7354476588e8df7c9ca0e0)
