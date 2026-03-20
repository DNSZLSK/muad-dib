/**
 * MUAD'DIB Configuration Loader
 *
 * Loads and validates .muaddibrc.json configuration files.
 * All fields are optional — missing values fall back to hardcoded defaults.
 *
 * Configurable: riskThresholds, maxFileSize, severityWeights
 * NOT configurable: ADR_THRESHOLD, BENIGN_THRESHOLD, GT_THRESHOLD (evaluation constants),
 *   FP_COUNT_THRESHOLDS, CONFIDENCE_FACTORS (too granular, modifying without expertise breaks the model)
 *
 * Security: parsed into Object.create(null) to prevent prototype pollution.
 * Config files > 10KB are rejected (no legitimate config is that large).
 */

const fs = require('fs');
const path = require('path');

const MAX_CONFIG_SIZE = 10 * 1024; // 10KB

const DEFAULTS = Object.freeze({
  riskThresholds: Object.freeze({ critical: 75, high: 50, medium: 25 }),
  maxFileSize: 10 * 1024 * 1024, // 10MB
  severityWeights: Object.freeze({ critical: 25, high: 10, medium: 3, low: 1 })
});

const VALID_TOP_KEYS = new Set(['riskThresholds', 'maxFileSize', 'severityWeights']);
const PROTO_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/**
 * Load and parse a JSON config file.
 * Uses JSON.parse (never require) to prevent code execution.
 * @param {string} filePath - absolute path to config file
 * @returns {{ raw: object|null, error: string|null }}
 */
function loadConfigFile(filePath) {
  try {
    const stat = fs.statSync(filePath);
    if (stat.size > MAX_CONFIG_SIZE) {
      return { raw: null, error: `Config file exceeds 10KB limit (${stat.size} bytes)` };
    }
    const content = fs.readFileSync(filePath, 'utf8');
    // Parse into null-prototype object to prevent prototype pollution
    const parsed = JSON.parse(content);
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      return { raw: null, error: 'Config file must contain a JSON object' };
    }
    // Deep copy into null-prototype objects
    const safe = Object.create(null);
    for (const key of Object.keys(parsed)) {
      if (typeof parsed[key] === 'object' && parsed[key] !== null && !Array.isArray(parsed[key])) {
        const inner = Object.create(null);
        for (const k of Object.keys(parsed[key])) {
          inner[k] = parsed[key][k];
        }
        safe[key] = inner;
      } else {
        safe[key] = parsed[key];
      }
    }
    return { raw: safe, error: null };
  } catch (err) {
    if (err.code === 'ENOENT') {
      return { raw: null, error: null }; // file not found is not an error for auto-detection
    }
    return { raw: null, error: `Failed to parse config: ${err.message}` };
  }
}

/**
 * Validate a parsed config object.
 * @param {object} raw - parsed config (null-prototype object)
 * @returns {{ config: object|null, warnings: string[], errors: string[] }}
 */
function validateConfig(raw) {
  const warnings = [];
  const errors = [];
  const config = Object.create(null);

  if (!raw) return { config: null, warnings, errors };

  // Check for prototype pollution keys at all levels
  for (const key of Object.keys(raw)) {
    if (PROTO_KEYS.has(key)) {
      errors.push(`Forbidden key "${key}" detected (prototype pollution attempt)`);
      return { config: null, warnings, errors };
    }
    if (typeof raw[key] === 'object' && raw[key] !== null) {
      for (const k of Object.keys(raw[key])) {
        if (PROTO_KEYS.has(k)) {
          errors.push(`Forbidden key "${key}.${k}" detected (prototype pollution attempt)`);
          return { config: null, warnings, errors };
        }
      }
    }
  }

  // Check for unknown top-level keys
  for (const key of Object.keys(raw)) {
    if (!VALID_TOP_KEYS.has(key)) {
      warnings.push(`Unknown config key "${key}" — ignored`);
    }
  }

  // Validate riskThresholds
  if (raw.riskThresholds !== undefined) {
    const rt = raw.riskThresholds;
    if (typeof rt !== 'object' || rt === null || Array.isArray(rt)) {
      errors.push('riskThresholds must be an object');
    } else {
      const validKeys = new Set(['critical', 'high', 'medium']);
      for (const k of Object.keys(rt)) {
        if (!validKeys.has(k)) {
          warnings.push(`Unknown riskThresholds key "${k}" — ignored`);
        }
      }
      const vals = Object.create(null);
      for (const k of ['critical', 'high', 'medium']) {
        if (rt[k] !== undefined) {
          if (typeof rt[k] !== 'number' || !Number.isFinite(rt[k])) {
            errors.push(`riskThresholds.${k} must be a finite number`);
          } else if (rt[k] <= 0) {
            errors.push(`riskThresholds.${k} must be > 0 (got ${rt[k]})`);
          } else {
            vals[k] = rt[k];
          }
        } else {
          vals[k] = DEFAULTS.riskThresholds[k];
        }
      }
      // Ordering: critical > high > medium
      if (!errors.length) {
        const c = vals.critical, h = vals.high, m = vals.medium;
        if (c <= h || h <= m) {
          errors.push(`riskThresholds ordering violation: critical (${c}) > high (${h}) > medium (${m}) required`);
        }
      }
      if (!errors.length) {
        config.riskThresholds = vals;
        // Warn if thresholds are relaxed beyond defaults
        if ((vals.critical > DEFAULTS.riskThresholds.critical) ||
            (vals.high > DEFAULTS.riskThresholds.high) ||
            (vals.medium > DEFAULTS.riskThresholds.medium)) {
          warnings.push('Risk thresholds relaxed — detection sensitivity reduced');
        }
      }
    }
  }

  // Validate maxFileSize
  if (raw.maxFileSize !== undefined) {
    const mfs = raw.maxFileSize;
    if (typeof mfs !== 'number' || !Number.isFinite(mfs) || !Number.isInteger(mfs)) {
      errors.push('maxFileSize must be a finite integer');
    } else if (mfs < 1024 * 1024) {
      errors.push(`maxFileSize must be >= 1MB (got ${mfs})`);
    } else if (mfs > 100 * 1024 * 1024) {
      errors.push(`maxFileSize must be <= 100MB (got ${mfs})`);
    } else {
      config.maxFileSize = mfs;
    }
  }

  // Validate severityWeights
  if (raw.severityWeights !== undefined) {
    const sw = raw.severityWeights;
    if (typeof sw !== 'object' || sw === null || Array.isArray(sw)) {
      errors.push('severityWeights must be an object');
    } else {
      const validKeys = new Set(['critical', 'high', 'medium', 'low']);
      for (const k of Object.keys(sw)) {
        if (!validKeys.has(k)) {
          warnings.push(`Unknown severityWeights key "${k}" — ignored`);
        }
      }
      const vals = Object.create(null);
      for (const k of ['critical', 'high', 'medium', 'low']) {
        if (sw[k] !== undefined) {
          if (typeof sw[k] !== 'number' || !Number.isFinite(sw[k])) {
            errors.push(`severityWeights.${k} must be a finite number`);
          } else if (sw[k] < 0) {
            errors.push(`severityWeights.${k} must be >= 0 (got ${sw[k]})`);
          } else {
            vals[k] = sw[k];
          }
        } else {
          vals[k] = DEFAULTS.severityWeights[k];
        }
      }
      // Ordering: critical >= high >= medium >= low
      if (!errors.length) {
        const c = vals.critical, h = vals.high, m = vals.medium, l = vals.low;
        if (c < h || h < m || m < l) {
          errors.push(`severityWeights ordering violation: critical (${c}) >= high (${h}) >= medium (${m}) >= low (${l}) required`);
        }
      }
      if (!errors.length) {
        config.severityWeights = vals;
      }
    }
  }

  const hasKeys = Object.keys(config).length > 0;
  return { config: hasKeys ? config : null, warnings, errors };
}

/**
 * Resolve which config file to load.
 * Priority: --config <path> > .muaddibrc.json at targetPath root
 * @param {string} targetPath - scan target directory
 * @param {string|null} configPath - explicit --config path (or null)
 * @returns {{ config: object|null, warnings: string[], errors: string[], source: string|null }}
 */
function resolveConfig(targetPath, configPath) {
  // Explicit --config path
  if (configPath) {
    const absPath = path.isAbsolute(configPath) ? configPath : path.resolve(configPath);
    if (!fs.existsSync(absPath)) {
      return { config: null, warnings: [], errors: [`Config file not found: ${configPath}`], source: null };
    }
    const { raw, error } = loadConfigFile(absPath);
    if (error) {
      return { config: null, warnings: [], errors: [error], source: null };
    }
    const result = validateConfig(raw);
    if (result.config) {
      result.warnings.unshift(`Loaded custom thresholds from ${configPath}`);
    }
    result.source = configPath;
    return result;
  }

  // Auto-detect .muaddibrc.json at target root
  const rcPath = path.join(targetPath, '.muaddibrc.json');
  if (!fs.existsSync(rcPath)) {
    return { config: null, warnings: [], errors: [], source: null };
  }
  const { raw, error } = loadConfigFile(rcPath);
  if (error) {
    // Auto-detected config with errors is a warning, not a fatal error
    return { config: null, warnings: [`[CONFIG] ${error} — .muaddibrc.json ignored`], errors: [], source: null };
  }
  const result = validateConfig(raw);
  if (result.config) {
    result.warnings.unshift('Loaded custom thresholds from .muaddibrc.json');
  }
  result.source = rcPath;
  return result;
}

module.exports = { DEFAULTS, loadConfigFile, validateConfig, resolveConfig };
