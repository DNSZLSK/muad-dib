const m = require('./metrics/v2.2.6.json');
console.log('=== BENIGN FPR RESULTS (50 packages) ===');
console.log('TPR:', m.groundTruth.tpr*100+'%');
console.log('FPR:', m.benign.fpr*100+'%', '('+m.benign.flagged+'/'+m.benign.scanned+')');
console.log('ADR:', m.adversarial.adr*100+'%');
console.log();
console.log('=== FALSE POSITIVES (score > 20) ===');
const fps = m.benign.details.filter(d => d.flagged).sort((a,b) => b.score - a.score);
fps.forEach(fp => {
  console.log(fp.name+': score '+fp.score);
  const types = {};
  (fp.threats||[]).forEach(t => { types[t.type] = (types[t.type]||0)+1; });
  Object.entries(types).sort((a,b)=>b[1]-a[1]).forEach(([k,v]) => console.log('  '+k+': '+v));
});
console.log();
console.log('=== NON-FLAGGED BUT ELEVATED (score > 0) ===');
m.benign.details.filter(d => !d.flagged && d.score > 0).sort((a,b) => b.score - a.score).forEach(d => console.log(d.name+': score '+d.score));
console.log();
console.log('=== THREAT TYPE FREQUENCY ===');
const allTypes = {};
fps.forEach(fp => {
  (fp.threats||[]).forEach(t => { allTypes[t.type] = (allTypes[t.type]||0)+1; });
});
Object.entries(allTypes).sort((a,b)=>b[1]-a[1]).forEach(([k,v]) => console.log('  '+k+': '+v));
