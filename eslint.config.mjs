import js from "@eslint/js";
import globals from "globals";
import security from "eslint-plugin-security";
import { defineConfig } from "eslint/config";

export default defineConfig([
  {
    files: ["**/*.{js,mjs,cjs}"],
    plugins: { js, security },
    extends: ["js/recommended"],
    languageOptions: {
      globals: globals.node
    },
    rules: {
      "no-unused-vars": ["error", { "argsIgnorePattern": "^_", "varsIgnorePattern": "^_" }],
      "security/detect-buffer-noassert": "warn",
      "security/detect-child-process": "warn",
      "security/detect-disable-mustache-escape": "warn",
      "security/detect-eval-with-expression": "warn",
      "security/detect-new-buffer": "warn",
      "security/detect-no-csrf-before-method-override": "warn",
      "security/detect-non-literal-fs-filename": "warn",
      "security/detect-non-literal-regexp": "warn",
      "security/detect-non-literal-require": "warn",
      "security/detect-object-injection": "warn",
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
    ignores: ["node_modules/**", "tests/**", "vscode-extension/**"]
  }
]);