// Shared REHABILITATED_PACKAGES — single source of truth
// Packages that were temporarily compromised but are now safe
// These packages will NOT be blocked (except specific compromised versions)
const REHABILITATED_PACKAGES = {
  // September 2025 - Massive compromise via phishing, fixed within hours
  'chalk': {
    compromised: [],
    safe: true,
    note: 'Compromised Sept 2025, malicious versions removed from npm'
  },
  'debug': {
    compromised: [],
    safe: true,
    note: 'Compromised Sept 2025, quickly fixed'
  },
  'ansi-styles': {
    compromised: [],
    safe: true,
    note: 'Compromised Sept 2025, quickly fixed'
  },
  'strip-ansi': {
    compromised: [],
    safe: true,
    note: 'Compromised Sept 2025, quickly fixed'
  },
  'wrap-ansi': {
    compromised: [],
    safe: true,
    note: 'Compromised Sept 2025, quickly fixed'
  },
  'is-arrayish': {
    compromised: [],
    safe: true,
    note: 'Compromised Sept 2025, quickly fixed'
  },
  'simple-swizzle': {
    compromised: [],
    safe: true,
    note: 'Compromised Sept 2025, quickly fixed'
  },
  'color-convert': {
    compromised: [],
    safe: true,
    note: 'Compromised Sept 2025, quickly fixed'
  },
  'supports-color': {
    compromised: [],
    safe: true,
    note: 'Compromised Sept 2025, quickly fixed'
  },
  'has-flag': {
    compromised: [],
    safe: true,
    note: 'Compromised Sept 2025, quickly fixed'
  },

  // Packages with specific compromised versions (not all)
  'ua-parser-js': {
    compromised: ['0.7.29', '0.8.0', '1.0.0'],
    safe: false,
    note: 'Specific versions compromised Oct 2021'
  },
  'coa': {
    compromised: ['2.0.3', '2.0.4', '2.1.1', '2.1.3', '3.0.1', '3.1.3'],
    safe: false,
    note: 'Specific versions compromised Nov 2021'
  },
  'rc': {
    compromised: ['1.2.9', '1.3.9', '2.3.9'],
    safe: false,
    note: 'Specific versions compromised Nov 2021'
  },

  // MUAD'DIB self-allowlisting (only the tool itself, not deps — deps must pass IOC checks)
  'muaddib-scanner': {
    compromised: [],
    safe: true,
    note: 'Our package — self-allowlisted to avoid self-flagging during scan'
  }
};

module.exports = { REHABILITATED_PACKAGES };
