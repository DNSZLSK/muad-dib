import js from "@eslint/js";
import globals from "globals";
import security from "eslint-plugin-security";
import { defineConfig } from "eslint/config";

export default defineConfig([
  {
    files: ["**/*.{js,mjs,cjs}"],
    plugins: { js, security },
    extends: ["js/recommended"],
    // A stale `eslint-disable` silently hides the next real finding on that line.
    linterOptions: { reportUnusedDisableDirectives: "error" },
    languageOptions: {
      globals: globals.node
    },
    rules: {
      "no-unused-vars": ["error", { "argsIgnorePattern": "^_", "varsIgnorePattern": "^_" }],
      // builtinGlobals:false is ESLint's historical default. `js/recommended` (ESLint 10)
      // enables it, which flags legitimate `const crypto = require('crypto')` (Node module,
      // distinct from the WebCrypto `crypto` global) and the `process` pipeline function.
      "no-redeclare": ["error", { "builtinGlobals": false }],
      // Best-effort cleanup catches (unlinkSync of temp files, signal429, etc.) are intentional.
      "no-empty": ["error", { "allowEmptyCatch": true }],
      "security/detect-buffer-noassert": "warn",
      "security/detect-child-process": "warn",
      "security/detect-disable-mustache-escape": "warn",
      "security/detect-eval-with-expression": "warn",
      "security/detect-new-buffer": "warn",
      "security/detect-no-csrf-before-method-override": "warn",
      // Off (2026-11-14, 1074 of 1121 warnings, none actionable): a scanner reads the files of the
      // package under analysis by design (non-literal fs paths everywhere), and object-injection
      // flags every obj[variable] access. The real risk behind the latter, prototype pollution,
      // is handled in code (DANGEROUS_KEYS, JSON.parse own keys) and fuzzed (tests/fuzz-test.js,
      // real "__proto__" keys). Keeping 1074 noise warnings hid the few that matter (ReDoS).
      "security/detect-non-literal-fs-filename": "off",
      "security/detect-non-literal-regexp": "warn",
      "security/detect-non-literal-require": "warn",
      "security/detect-object-injection": "off",
      "security/detect-possible-timing-attacks": "warn",
      "security/detect-pseudoRandomBytes": "warn",
      "security/detect-unsafe-regex": "warn",
      "security/detect-bidi-characters": "warn"
    }
  },
  {
    files: ["**/*.js"],
    languageOptions: {
      sourceType: "script"
    }
  },
  {
    // Except where a path segment comes from outside (archive entries, registry package names,
    // downloaded feeds): there a non-literal path can escape the target directory (zip slip,
    // "../" in a package name), so every hit must be justified or guarded.
    files: [
      "src/shared/download.js",
      "src/shared/extract-pool.js",
      "src/shared/extract-pool-worker.js",
      "src/shared/extract-worker.js",
      "src/monitor/tarball-archive.js",
      "src/monitor/tarball-prefetch.js",
      "src/ioc/scraper.js",
      "src/ioc/updater.js",
      "src/sandbox/index.js",
      "src/commands/safe-install.js"
    ],
    rules: {
      "security/detect-non-literal-fs-filename": "warn"
    }
  },
  {
    ignores: ["node_modules/**", "tests/**", "vscode-extension/**"]
  }
]);