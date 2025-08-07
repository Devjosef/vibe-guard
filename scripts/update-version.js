const fs = require('fs');
const pkg = require('../package.json');
const content = `export const VERSION = '${pkg.version}';\n`;
fs.writeFileSync('src/types/version.ts', content); 