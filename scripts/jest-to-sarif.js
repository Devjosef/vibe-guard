const fs = require('fs');
const path = require('path');

// Regex for capturing file:line:column in stack traces
// Matches formats:
//  at Object.<anonymous> (/path/to/file.js:10:5)
//  at /path/to/file.js:10:5
//  at file:///path/to/file.js:10:5
const STACK_LOCATION_RE = /(?:\()?((?:file:\/\/\/)?[^\s():]+?):(\d+):(\d+)(?:\))?/gm;

function extractStackLocations(text) {
  const matches = [];
  if (!text) return matches;
  let m;
  while ((m = STACK_LOCATION_RE.exec(text)) !== null) {
    let filePath = m[1];
    const line = parseInt(m[2], 10);
    const col = parseInt(m[3], 10);

    if (filePath.startsWith('file:///')) {
      filePath = filePath.replace(/^file:\/\/\//, '');
    }

    // Deprioritize internal node frames and node_modules for better stack trace analysis
    const lower = filePath.toLowerCase();
    if (lower.includes('node:internal') || lower.includes('internal/') || lower.includes('node_modules')) {
      // still collect but deprioritize
      matches.push({ filePath, line, col, deprioritize: true });
    } else {
      matches.push({ filePath, line, col, deprioritize: false });
    }
  }

  // prioritize non-deprioritized frames
  matches.sort((a, b) => (a.deprioritize === b.deprioritize ? 0 : a.deprioritize ? 1 : -1));
  return matches;
}

function loadJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    console.error('Failed to read JSON from', file, e.message);
    process.exitCode = 2;
    return null;
  }
}

function toSarif(jestJson) {
  const runs = [];
  // attempt to read installed jest package version so SARIF includes tool version
  let jestVersion;
  try {
    // eslint-disable-next-line global-require,import/no-extraneous-dependencies
    jestVersion = require('jest/package.json').version;
  } catch (e) {
    jestVersion = undefined;
  }

  const tool = {
    driver: {
      name: 'jest',
      informationUri: 'https://jestjs.io/',
      version: jestVersion,
      rules: []
    }
  };

  const results = [];

  if (!jestJson || !Array.isArray(jestJson.testResults)) {
    return null;
  }

  // collect rule metadata: use assertion title as rule id for now
  const ruleIds = new Map();

  for (const testFile of jestJson.testResults) {
    for (const assertion of testFile.assertionResults || []) {
      const status = assertion.status; // 'passed'|'failed'|'skipped'
      const ruleId = (assertion.title || 'test-failure').slice(0, 80);

      if (!ruleIds.has(ruleId)) {
        ruleIds.set(ruleId, {
          id: ruleId,
          shortDescription: { text: assertion.title || 'Test failure' },
          fullDescription: { text: assertion.fullName || assertion.title || '' },
          properties: { tags: ['test'] }
        });
      }

      // Map Jest status to SARIF levels: failed->error, passed->note, skipped->none
      let level;
      if (status === 'failed') level = 'error';
      else if (status === 'passed') level = 'note';
      else if (status === 'skipped') level = 'none';
      else level = 'note';

      const message = (assertion.failureMessages || []).join('\n') || assertion.title || '';

      if (status === 'failed') {
        // extract multiple stack locations (prioritized)
        const stackLocations = extractStackLocations(message);
        if (stackLocations.length) {
          const locations = stackLocations.map(loc => {
            const fileUri = path.isAbsolute(loc.filePath) ? path.relative(process.cwd(), loc.filePath) : loc.filePath;
            return {
              physicalLocation: {
                artifactLocation: { uri: fileUri },
                region: { startLine: loc.line, startColumn: loc.col }
              }
            };
          });

          results.push({
            ruleId,
            level,
            message: { text: message },
            locations
          });
        } else {
          const fileUri = path.isAbsolute(testFile.name) ? path.relative(process.cwd(), testFile.name) : testFile.name;
          results.push({
            ruleId,
            level,
            message: { text: message },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: fileUri }
                }
              }
            ]
          });
        }
      } else {
        // passed or skipped: attach to the test file without region
        const fileUri = path.isAbsolute(testFile.name) ? path.relative(process.cwd(), testFile.name) : testFile.name;
        results.push({
          ruleId,
          level,
          message: { text: message },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: fileUri }
              }
            }
          ]
        });
      }
    }
  }

  // push collected rule metadata into tool.driver.rules
  tool.driver.rules = Array.from(ruleIds.values());

  runs.push({ tool, results });

  // include invocation/automation details if available from Jest JSON
  try {
    const summary = jestJson.numTotalTests !== undefined ? {
      toolExecutionNotifications: [],
      executionSuccessful: (jestJson.numFailedTests || 0) === 0,
      invocation: {
        startTime: jestJson.startTime ? new Date(jestJson.startTime).toISOString() : undefined,
        endTime: jestJson.endTime ? new Date(jestJson.endTime).toISOString() : undefined,
        commandLine: 'jest --json'
      }
    } : null;

   // if (summary) runs[0].invocation = summary.invocation;
  } catch (e) {
    // ignore
  }

  // Optional SARIF schema validation (if ajv and sarif-schema are installed)
  try {
    // eslint-disable-next-line global-require, import/no-extraneous-dependencies
    const Ajv = require('ajv');
    // eslint-disable-next-line global-require, import/no-extraneous-dependencies
    const sarifSchema = require('sarif-schema');
    const ajv = new Ajv({ allErrors: true, strict: false });
    const validate = ajv.compile(sarifSchema);
    const valid = validate({ $schema: 'ignore', version: '2.1.0', runs });
    if (!valid) {
      console.warn('SARIF validation failed:', validate.errors);
    }
  } catch (e) {
    // Ajv or sarif-schema not installed — skip validation quietly
  }

  return {
    $schema: 'https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json',
    version: '2.1.0',
    runs
  };
}

function main() {
  const input = process.argv[2] || 'jest-output.json';
  const output = process.argv[3] || 'test-results.sarif';

  const jestJson = loadJson(input);
  if (!jestJson) process.exit(2);

  const sarif = toSarif(jestJson);
  if (!sarif) {
    console.error('No sarif generated');
    process.exit(2);
  }

  fs.writeFileSync(output, JSON.stringify(sarif, null, 2), 'utf8');
  console.log('Wrote SARIF to', output);
}

if (require.main === module) main();
