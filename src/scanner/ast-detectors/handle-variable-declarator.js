'use strict';

const { getCallName } = require('../../utils.js');
const {
  SAFE_ENV_VARS,
  SAFE_ENV_PREFIXES,
  DANGEROUS_CMD_PATTERNS,
  MCP_CONFIG_PATHS,
  GIT_HOOKS
} = require('./constants.js');
const {
  isEnvSensitive,
  extractStringValue,
  countConcatOperands,
  resolveStringConcatWithVars,
  extractStringValueDeep,
  isStaticValue
} = require('./helpers.js');

function handleVariableDeclarator(node, ctx) {
  if (node.id?.type === 'Identifier') {
    // Track statically-assigned variables for dynamic_require qualification
    if (node.init && isStaticValue(node.init)) {
      ctx.staticAssignments.add(node.id.name);
    }

    // Track dynamic require vars + module aliases
    if (node.init?.type === 'CallExpression') {
      const initCallName = getCallName(node.init);
      if (initCallName === 'require' && node.init.arguments.length > 0) {
        const arg = node.init.arguments[0];
        if (arg.type !== 'Literal') {
          ctx.dynamicRequireVars.add(node.id.name);
        }
        // Track require('module') or require('node:module') aliases for Module._load detection
        const reqVal = extractStringValueDeep(arg);
        if (reqVal === 'module') {
          if (!ctx.moduleAliases) ctx.moduleAliases = new Set();
          ctx.moduleAliases.add(node.id.name);
        }
      }
    }
    // Track variables assigned dangerous command strings
    const strVal = extractStringValue(node.init);
    if (strVal && DANGEROUS_CMD_PATTERNS.some(p => p.test(strVal))) {
      ctx.dangerousCmdVars.set(node.id.name, strVal);
    }

    // Track variables assigned temp/executable file paths
    if (strVal && /^\/tmp\/|^\/var\/tmp\/|\\temp\\/i.test(strVal)) {
      ctx.execPathVars.set(node.id.name, strVal);
    }

    // Track variables that alias globalThis or global (e.g. const g = globalThis)
    if (node.init?.type === 'Identifier' &&
        (node.init.name === 'globalThis' || node.init.name === 'global' ||
         node.init.name === 'window' || node.init.name === 'self')) {
      ctx.globalThisAliases.add(node.id.name);
    }

    // B1: const E = eval; const F = Function;
    if (node.init?.type === 'Identifier' &&
        (node.init.name === 'eval' || node.init.name === 'Function')) {
      ctx.evalAliases.set(node.id.name, node.init.name);
    }
    // B1: const E = (x) => eval(x); const E = function(x) { return eval(x); }
    if ((node.init?.type === 'ArrowFunctionExpression' || node.init?.type === 'FunctionExpression') &&
        node.init.params?.length >= 1) {
      const body = node.init.body;
      if (body?.type === 'CallExpression') {
        const cn = getCallName(body);
        if (cn === 'eval' || cn === 'Function') ctx.evalAliases.set(node.id.name, cn);
      }
      if (body?.type === 'BlockStatement' && body.body?.length === 1 &&
          body.body[0].type === 'ReturnStatement' && body.body[0].argument?.type === 'CallExpression') {
        const cn = getCallName(body.body[0].argument);
        if (cn === 'eval' || cn === 'Function') ctx.evalAliases.set(node.id.name, cn);
      }
    }
    // B1 fix: const getEval = () => eval; — 0-param arrow/function returning eval/Function as value (not call)
    if ((node.init?.type === 'ArrowFunctionExpression' || node.init?.type === 'FunctionExpression')) {
      const body = node.init.body;
      // () => eval
      if (body?.type === 'Identifier' && (body.name === 'eval' || body.name === 'Function')) {
        ctx.evalAliases.set(node.id.name, body.name + '_factory');
      }
      // () => { return eval; }
      if (body?.type === 'BlockStatement' && body.body?.length === 1 &&
          body.body[0].type === 'ReturnStatement' &&
          body.body[0].argument?.type === 'Identifier' &&
          (body.body[0].argument.name === 'eval' || body.body[0].argument.name === 'Function')) {
        ctx.evalAliases.set(node.id.name, body.body[0].argument.name + '_factory');
      }
    }

    // Audit v3 B3: const AF = Object.getPrototypeOf(async function(){}).constructor
    // Blue Team v8: Extended to detect nested getPrototypeOf chains (2+ levels deep)
    if (node.init?.type === 'MemberExpression') {
      const initProp = node.init.computed
        ? (node.init.property?.type === 'Literal' ? String(node.init.property.value) : null)
        : node.init.property?.name;
      if (initProp === 'constructor' && node.init.object?.type === 'CallExpression') {
        const innerCall = node.init.object;
        if (innerCall.callee?.type === 'MemberExpression') {
          const innerObj = innerCall.callee.object;
          const innerPropName = innerCall.callee.property?.name;
          if (innerObj?.type === 'Identifier' &&
              (innerObj.name === 'Object' || innerObj.name === 'Reflect') &&
              innerPropName === 'getPrototypeOf' &&
              innerCall.arguments?.length >= 1) {
            const arg = innerCall.arguments[0];
            if (arg.type === 'FunctionExpression' && (arg.async || arg.generator)) {
              const kind = arg.async ? 'AsyncFunction' : 'GeneratorFunction';
              ctx.evalAliases.set(node.id.name, 'Function');
              // Emit CRITICAL at declaration — extracting constructor via prototype chain is never benign
              ctx.hasDynamicExec = true;
              ctx.threats.push({
                type: 'dangerous_constructor',
                severity: 'CRITICAL',
                message: `${kind} constructor extracted via Object.getPrototypeOf() into "${node.id.name}" — prototype chain code execution evasion.`,
                file: ctx.relFile
              });
            }
            // Blue Team v8: Nested getPrototypeOf — Object.getPrototypeOf(Object.getPrototypeOf(...)).constructor
            // Walking up prototype chain 2+ levels to reach Function constructor from any object
            if (arg.type === 'CallExpression' && arg.callee?.type === 'MemberExpression' &&
                arg.callee.property?.name === 'getPrototypeOf') {
              ctx.evalAliases.set(node.id.name, 'Function');
              ctx.hasDynamicExec = true;
              ctx.threats.push({
                type: 'dangerous_constructor',
                severity: 'CRITICAL',
                message: `Nested Object.getPrototypeOf() chain (2+ levels) + .constructor into "${node.id.name}" — deep prototype traversal to reach Function constructor.`,
                file: ctx.relFile
              });
            }
            // Blue Team v8b (A3): Object.getPrototypeOf(variable).constructor
            // When a variable (possibly holding a prototype chain result) is passed to
            // getPrototypeOf and .constructor is extracted — prototype chain traversal attack.
            // Covers: const C = Object.getPrototypeOf(protoVar).constructor
            if (arg.type === 'Identifier') {
              ctx.evalAliases.set(node.id.name, 'Function');
              ctx.hasDynamicExec = true;
              ctx.threats.push({
                type: 'prototype_chain_constructor',
                severity: 'CRITICAL',
                message: `Object.getPrototypeOf(${arg.name}).constructor extracted into "${node.id.name}" — prototype chain traversal to reach Function constructor.`,
                file: ctx.relFile
              });
            }
          }
        }
      }
    }

    // B1 fix: const compiler = getCompiler() where getCompiler is eval_factory
    if (node.init?.type === 'CallExpression' &&
        node.init.callee?.type === 'Identifier' &&
        ctx.evalAliases?.has(node.init.callee.name)) {
      const aliased = ctx.evalAliases.get(node.init.callee.name);
      if (aliased.endsWith('_factory')) {
        const baseName = aliased.replace('_factory', '');
        ctx.evalAliases.set(node.id.name, baseName);
      }
    }

    // B5: Track object literal string properties
    if (node.init?.type === 'ObjectExpression') {
      const propMap = new Map();
      for (const prop of node.init.properties) {
        if (prop.type !== 'Property') continue;
        const key = prop.key?.type === 'Identifier' ? prop.key.name :
                    (prop.key?.type === 'Literal' ? String(prop.key.value) : null);
        const val = extractStringValueDeep(prop.value);
        if (key && val) propMap.set(key, val);
      }
      if (propMap.size > 0) ctx.objectPropertyMap.set(node.id.name, propMap);
    }

    // Track initial string values for reassignment tracking
    if (strVal !== null && strVal !== undefined) {
      ctx.stringVarValues.set(node.id.name, strVal);
    }

    // Blue Team v8b (B7): Track path.join() results where last arg is an image/binary filename
    // Enables steganographic payload detection when the variable is used with fs.readFileSync
    if (!strVal && node.init?.type === 'CallExpression') {
      const initCallName = getCallName(node.init);
      if ((initCallName === 'join' || initCallName === 'resolve') &&
          node.init.callee?.type === 'MemberExpression' &&
          node.init.arguments?.length > 0) {
        const lastArg = node.init.arguments[node.init.arguments.length - 1];
        if (lastArg?.type === 'Literal' && typeof lastArg.value === 'string') {
          // Store the last path component so image extension check works later
          ctx.stringVarValues.set(node.id.name, lastArg.value);
        }
      }
    }

    // Track variables assigned from require.cache[...] (module cache references)
    // Used to detect writes to cached module exports (require.cache poisoning)
    if (node.init?.type === 'MemberExpression' && node.init.computed) {
      const obj = node.init.object;
      if (obj?.type === 'MemberExpression' &&
          obj.object?.type === 'Identifier' && obj.object.name === 'require' &&
          obj.property?.type === 'Identifier' && obj.property.name === 'cache') {
        ctx.requireCacheVars.add(node.id.name);
      }
    }

    // Track variables assigned from BinaryExpression with '+' (string concatenation building)
    // Used to detect setTimeout(concatVar, delay) — eval via timer with built string
    // FP fix: only track when at least one operand is demonstrably a string (literal, template,
    // or known string var). Filters out arithmetic `var e = a + 1` in minified code.
    if (node.init?.type === 'BinaryExpression' && node.init.operator === '+') {
      const left = node.init.left;
      const right = node.init.right;
      const isStringOperand = (n) =>
        (n.type === 'Literal' && typeof n.value === 'string') ||
        n.type === 'TemplateLiteral' ||
        (n.type === 'Identifier' && ctx.stringVarValues?.has(n.name)) ||
        (n.type === 'Identifier' && ctx.stringBuildVars?.has(n.name));
      if (isStringOperand(left) || isStringOperand(right)) {
        ctx.stringBuildVars.add(node.id.name);
        // Audit v3 B2: Resolve concat value and track for split-entropy detection
        const operands = countConcatOperands(node.init);
        if (operands >= 3) {
          const resolved = resolveStringConcatWithVars(node.init, ctx.stringVarValues);
          if (resolved && resolved.length >= 20) {
            ctx.concatValues.set(node.id.name, { value: resolved, operands });
          }
        }
      }
    }

    // Track object variables with Proxy trap properties (set/get/apply/construct)
    // Used to detect new Proxy(target, handlerVar) when handler is not inline
    if (node.init?.type === 'ObjectExpression') {
      const hasTrap = node.init.properties?.some(p =>
        p.key?.type === 'Identifier' && ['set', 'get', 'apply', 'construct'].includes(p.key.name)
      );
      if (hasTrap) {
        ctx.proxyHandlerVars.add(node.id.name);
      }
    }

    // Track variables assigned from path.join containing .github/workflows
    if (node.init?.type === 'CallExpression' && node.init.callee?.type === 'MemberExpression') {
      const obj = node.init.callee.object;
      const prop = node.init.callee.property;
      if (obj?.type === 'Identifier' && obj.name === 'path' &&
          prop?.type === 'Identifier' && (prop.name === 'join' || prop.name === 'resolve')) {
        const joinArgs = node.init.arguments.map(a => extractStringValueDeep(a) || '').join('/');
        if (/\.github[\\/\/]workflows/i.test(joinArgs) || /\.github[\\/\/]actions/i.test(joinArgs)) {
          ctx.workflowPathVars.add(node.id.name);
        }
        // Propagate: path.join(workflowPathVar, ...) inherits tracking
        else if (node.init.arguments.some(a => a.type === 'Identifier' && ctx.workflowPathVars.has(a.name))) {
          ctx.workflowPathVars.add(node.id.name);
        }
        // Track path.join that resolves to .git/hooks (concat fragments included)
        if (/\.git[\\/\/]hooks/i.test(joinArgs) ||
            (GIT_HOOKS.some(h => joinArgs.includes(h)) && joinArgs.includes('.git'))) {
          ctx.gitHooksPathVars.set(node.id.name, joinArgs);
        }
        // Propagate: path.join(gitHooksPathVar, ...) inherits tracking
        else if (node.init.arguments.some(a => a.type === 'Identifier' && ctx.gitHooksPathVars.has(a.name))) {
          const parentPath = node.init.arguments.map(a => {
            if (a.type === 'Identifier' && ctx.gitHooksPathVars.has(a.name)) return ctx.gitHooksPathVars.get(a.name);
            return extractStringValueDeep(a) || '';
          }).join('/');
          ctx.gitHooksPathVars.set(node.id.name, parentPath);
        }
        // Track path.join that resolves to IDE config paths (.claude/, .cursor/, etc.)
        const joinLower = joinArgs.toLowerCase();
        if (MCP_CONFIG_PATHS.some(p => joinLower.includes(p.toLowerCase()))) {
          ctx.ideConfigPathVars.set(node.id.name, joinArgs);
        }
        // Propagate: path.join(ideConfigPathVar, ...) inherits tracking
        else if (node.init.arguments.some(a => a.type === 'Identifier' && ctx.ideConfigPathVars.has(a.name))) {
          const parentPath = node.init.arguments.map(a => {
            if (a.type === 'Identifier' && ctx.ideConfigPathVars.has(a.name)) return ctx.ideConfigPathVars.get(a.name);
            return extractStringValueDeep(a) || '';
          }).join('/');
          ctx.ideConfigPathVars.set(node.id.name, parentPath);
        }
      }
    }
  }

  // Audit v3 bypass fix: Array destructuring eval alias: const [fn] = [eval]
  if (node.id?.type === 'ArrayPattern' && node.init?.type === 'ArrayExpression') {
    const elements = node.init.elements;
    const patterns = node.id.elements;
    for (let i = 0; i < Math.min(elements?.length || 0, patterns?.length || 0); i++) {
      const el = elements[i];
      const pat = patterns[i];
      if (el?.type === 'Identifier' && pat?.type === 'Identifier') {
        if (el.name === 'eval' || el.name === 'Function') {
          ctx.evalAliases.set(pat.name, el.name);
        }
      }
    }
  }

  // Audit v3 B3: Destructuring of require('module') → track _load as direct function alias
  if (node.id?.type === 'ObjectPattern' &&
      node.init?.type === 'CallExpression') {
    const initCallName = getCallName(node.init);
    if (initCallName === 'require' && node.init.arguments.length > 0) {
      const reqVal = extractStringValueDeep(node.init.arguments[0]);
      if (reqVal === 'module') {
        for (const prop of node.id.properties) {
          if (prop.type === 'Property' && prop.key?.type === 'Identifier') {
            const localName = prop.value?.type === 'Identifier' ? prop.value.name : prop.key.name;
            if (prop.key.name === '_load') {
              ctx.moduleLoadDirectAliases.add(localName);
            }
          }
        }
      }
    }
  }

  // Audit v3 B3: Destructuring of globalThis/global → track eval/Function aliases
  if (node.id?.type === 'ObjectPattern' &&
      node.init?.type === 'Identifier' &&
      (node.init.name === 'globalThis' || node.init.name === 'global' ||
       node.init.name === 'window' || node.init.name === 'self' ||
       ctx.globalThisAliases.has(node.init.name))) {
    for (const prop of node.id.properties) {
      if (prop.type === 'Property' && prop.key?.type === 'Identifier') {
        const originalName = prop.key.name;
        const localName = prop.value?.type === 'Identifier' ? prop.value.name : prop.key.name;
        if (originalName === 'eval' || originalName === 'Function') {
          ctx.evalAliases.set(localName, originalName);
        }
      }
    }
  }

  // Batch 2: Detect destructuring of process.env: const { TOKEN, SECRET } = process.env
  if (node.id?.type === 'ObjectPattern' &&
      node.init?.type === 'MemberExpression' &&
      node.init.object?.type === 'Identifier' && node.init.object.name === 'process' &&
      node.init.property?.type === 'Identifier' && node.init.property.name === 'env') {
    for (const prop of node.id.properties) {
      if (prop.type === 'Property' && prop.key?.type === 'Identifier') {
        const envVar = prop.key.name;
        if (SAFE_ENV_VARS.includes(envVar)) continue;
        const envLower = envVar.toLowerCase();
        if (SAFE_ENV_PREFIXES.some(p => envLower.startsWith(p))) continue;
        if (isEnvSensitive(envVar)) {
          ctx.threats.push({
            type: 'env_access',
            severity: 'HIGH',
            message: `Destructured access to sensitive env var: const { ${envVar} } = process.env.`,
            file: ctx.relFile
          });
        }
      }
      // RestElement: const { ...all } = process.env → env harvesting
      if (prop.type === 'RestElement') {
        ctx.threats.push({
          type: 'env_harvesting_dynamic',
          severity: 'HIGH',
          message: 'Environment variable harvesting via rest destructuring: const { ...rest } = process.env.',
          file: ctx.relFile
        });
      }
    }
  }
}


module.exports = { handleVariableDeclarator };
