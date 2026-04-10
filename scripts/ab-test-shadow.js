const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const newModel = require('../src/ml/model-trees-shadow.js');
const oldModelJs = execSync('git show master:src/ml/model-trees-shadow.js', { encoding: 'utf8' });
const oldTmp = path.join(require('os').tmpdir(), 'old-model-trees.js');
fs.writeFileSync(oldTmp, oldModelJs);
const oldModel = require(oldTmp);
console.log('NEW: features=' + newModel.features.length + ' trees=' + newModel.trees.length + ' threshold=' + newModel.threshold);
console.log('OLD: features=' + oldModel.features.length + ' trees=' + oldModel.trees.length + ' threshold=' + oldModel.threshold);
function traverse(tree, features) { let i = 0; while (i < tree.length) { const node = tree[i]; if (node.f === -1) return node.v; i = features[node.f] < node.t ? node.y : node.n; } return 0; }
function sigmoid(x) { return 1 / (1 + Math.exp(-x)); }
function predict(model, record) { const feat = model.features.map(f => record[f] || 0); const margin = model.trees.reduce((s, t) => s + traverse(t, feat), 0); return sigmoid(margin); }
const content = fs.readFileSync(path.join(__dirname, '..', 'data', 'ml-training-curated-benign.jsonl'), 'utf8');
const records = content.split('\n').filter(l => l.trim()).map(l => JSON.parse(l));
const highScore = records.filter(r => (r.score || 0) >= 20);
console.log('Testing on ' + highScore.length + ' high-score curated_benign records');
let oldF = 0, newF = 0;
for (const r of highScore) { const op = predict(oldModel, r); const np = predict(newModel, r); if (op >= oldModel.threshold) oldF++; if (np >= newModel.threshold) newF++; }
console.log('OLD model: ' + oldF + '/' + highScore.length + ' flagged (' + (100*oldF/highScore.length).toFixed(1) + '%)');
console.log('NEW model: ' + newF + '/' + highScore.length + ' flagged (' + (100*newF/highScore.length).toFixed(1) + '%)');
if (newF < oldF) { console.log('[WIN] ' + (oldF - newF) + ' fewer false positives'); } else if (newF > oldF) { console.log('[LOSS] ' + (newF - oldF) + ' more false positives'); } else { console.log('[TIE]'); }
