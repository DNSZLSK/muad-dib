const DIST_FILE_RE = /(?:^|[/\\])(?:dist|build)[/\\]|\.min\.js$|\.bundle\.js$/i;
console.log('dist\\chunks\\file.js:', DIST_FILE_RE.test('dist\\chunks\\file.js'));
console.log('dist/chunks/file.js:', DIST_FILE_RE.test('dist/chunks/file.js'));
console.log('package\\dist\\file.js:', DIST_FILE_RE.test('package\\dist\\file.js'));
console.log('src\\index.js:', DIST_FILE_RE.test('src\\index.js'));
