# Vendored binaries

Files in this directory are committed binaries that MUAD'DIB depends on at
runtime but does not pull from npm to keep the supply-chain audit surface
small.

## `tree-sitter-python.wasm`

WebAssembly grammar for parsing Python source. Used by `src/scanner/python-ast.js`
(MUADDIB-PYAST-* rules — TrapDoor PyPI gap, v2.11.42+) via `web-tree-sitter`.

- **Size**: 449 KB (449 862 bytes).
- **Source**: <https://github.com/tree-sitter/tree-sitter.github.io/raw/master/tree-sitter-python.wasm>
  (the canonical upstream repo where the tree-sitter team publishes the pre-compiled
  playground WASMs — same source consumed by Semgrep, Neovim, GitHub code search).
- **NOT** sourced from the third-party npm package `tree-sitter-wasms` (extra
  attack surface, no security guarantee on republished binaries).
- **Hash**: see `tree-sitter-python.wasm.sha256` (SHA-256, committed alongside).

### Update procedure

```bash
# 1. Download from upstream
curl -L -o src/vendor/tree-sitter-python.wasm \
  https://github.com/tree-sitter/tree-sitter.github.io/raw/master/tree-sitter-python.wasm

# 2. Recompute and overwrite the hash file
shasum -a 256 src/vendor/tree-sitter-python.wasm \
  > src/vendor/tree-sitter-python.wasm.sha256

# 3. Confirm against the upstream commit hash announced in
#    https://github.com/tree-sitter/tree-sitter-python/releases
#    (the WASM build for a given grammar version is reproducible).

# 4. Commit the binary + hash file together. Reviewers MUST diff the hash.
```

### Audit hook

A test in `tests/scanner/python-ast.test.js` re-computes the SHA-256 of the
checked-in WASM and asserts it matches `tree-sitter-python.wasm.sha256` — any
silent rewrite (rogue commit, repo tampering) fails the test suite.
