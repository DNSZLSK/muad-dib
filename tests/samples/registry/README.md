# Registry fixtures

Real npm registry documents (`registry.npmjs.org`), frozen for the monitor metadata lane tests. Each file is listed in `manifest.json` with the property it was chosen for; `tests/unit/registry-fixtures.test.js` checks that property on the document.

- Captured as served by the registry, gzipped. The only change: e-mail addresses are replaced by `user@example.invalid`. `sha256Original` is the hash of the document before that change.
- `dist-tags` reflect the capture date, not the publish date of the version named in the manifest.
- The `--abbreviated` file is the `application/vnd.npm.install-v1+json` document (no `time` field); the `--version-` file is the single-version document (`/<name>/<version>`).
