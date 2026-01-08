#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

const STACK_LOCATION_RE = /(?:\()?((?:file:\/\/\/)?[^\s():]+?):(\d+):(\d+)(?:\))?/gm;

function extractStackLocations(text) {
  const matches = [];
  if (!text) return matches;
  STACK_LOCATION_RE.lastIndex = 0;
  let m;
  while ((m = STACK_LOCATION_RE.exec(text)) !== null) {
    let filePath = m[1];
    const line = parseInt(m[2], 10);
    const col = parseInt(m[3], 10);
    if (filePath.startsWith('file:///')) filePath = filePath.replace(/^file:\/\/\//, '');
    const lower = filePath.toLowerCase();
    const deprioritize = lower.includes('node:internal') || lower.includes('internal/') || lower.includes('node_modules');
    matches.push({ filePath, line, col, deprioritize });
  }
  matches.sort((a, b) => (a.deprioritize === b.deprioritize ? 0 : a.deprioritize ? 1 : -1));
  return matches;
}

function loadJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    console.error(`Failed to parse JSON: ${file}\n${e.stack}`);
    process.exitCode = 2;
    return null;
  }
}

function toSarif(jestJson, opts = { includePassed: false, relativePaths: false }) {
  if (!jestJson || !Array.isArray(jestJson.testResults)) {
    console.error('Invalid Jest JSON structure.');
    return null;
  }

  let jestVersion;
  try {
    jestVersion = require('jest/package.json').version;
  } catch {
    jestVersion = undefined;
  }

  const ruleIds = new Map();
  const results = [];
  let total = 0, passed = 0, failed = 0, skipped = 0;

  const makeUri = (p) => {
    const abs = path.isAbsolute(p) ? path.resolve(p) : path.resolve(process.cwd(), p);
    let rel = path.relative(process.cwd(), abs).replace(/\\/g, '/');
    if (opts && opts.relativePaths) return rel;
    if (!rel.startsWith('/')) rel = '/' + rel;
    return 'file:///' + rel.replace(/^[\\/]+/, '');
  };

  for (const testFile of jestJson.testResults) {
    for (const assertion of testFile.assertionResults || []) {
      total++;
      switch (assertion.status) {
        case 'passed': passed++; break;
        case 'failed': failed++; break;
        case 'skipped': skipped++; break;
      }

      if (assertion.status === 'failed' || opts.includePassed) {
        const ruleId = (assertion.title || 'test-failure').slice(0, 80);
        if (!ruleIds.has(ruleId)) {
          ruleIds.set(ruleId, {
            id: ruleId,
            shortDescription: { text: assertion.title || 'Test failure' },
            fullDescription: { text: assertion.fullName || assertion.title || '' },
            properties: { tags: ['test'] }
          });
        }

        const message = (assertion.failureMessages || []).join('\n') || assertion.title || '';
        const stackLocations = extractStackLocations(message);

        const locations = stackLocations.length
          ? stackLocations.map(loc => ({
              physicalLocation: {
                artifactLocation: { uri: makeUri(loc.filePath) },
                region: { startLine: loc.line, startColumn: loc.col }
              }
            }))
          : [{
              physicalLocation: { artifactLocation: { uri: makeUri(testFile.name || 'unknown') } }
            }];

        const level = assertion.status === 'failed' ? 'error' : (assertion.status === 'passed' ? 'note' : 'none');
        results.push({ ruleId, level, message: { text: message }, locations });
      }
    }
  }

  console.log(`Jest results - total=${total}, passed=${passed}, failed=${failed}, skipped=${skipped}`);

  const tool = {
    driver: {
      name: 'jest',
      semanticVersion: jestVersion,
      informationUri: 'https://jestjs.io/',
      rules: Array.from(ruleIds.values())
    }
  };

  const run = {
    tool,
    results,
    invocations: [{
      commandLine: 'jest --json',
      executionSuccessful: failed === 0,
      startTimeUtc: jestJson.startTime ? new Date(jestJson.startTime).toISOString() : undefined,
      endTimeUtc: jestJson.endTime ? new Date(jestJson.endTime).toISOString() : undefined
    }]
  };

  const sarif = {
    $schema: 'https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json',
    version: '2.1.0',
    runs: [run]
  };

  try {
    const Ajv = require('ajv');
    const sarifSchema = require('sarif-schema');
    const ajv = new Ajv({ allErrors: true, strict: false });
    const validate = ajv.compile(sarifSchema);
    const valid = validate(sarif);
    if (!valid) console.warn('SARIF validation failed:', validate.errors);
  } catch {}

  return sarif;
}

function main() {
  const argv = process.argv.slice(2);
  const input = argv[0] || 'jest-output.json';
  const output = argv[1] || 'test-results.sarif';
  const includePassed = argv.includes('--include-passed');
  const relativePaths = argv.includes('--relative-paths');

  const jestJson = loadJson(input);
  if (!jestJson) process.exit(2);

  const sarif = toSarif(jestJson, { includePassed: includePassed, relativePaths: relativePaths });
  if (!sarif) {
    console.error('No SARIF generated.');
    process.exit(2);
  }

  fs.writeFileSync(output, JSON.stringify(sarif, null, 2), 'utf8');
  console.log(`Wrote SARIF results to ${output}`);
}

if (require.main === module)  main();

module.exports = { extractStackLocations, toSarif, loadJson };
