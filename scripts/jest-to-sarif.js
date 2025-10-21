// Minimal converter: Jest JSON -> SARIF (v2.1.0)
// Not a full fidelity converter; covers tests and failures mapping to SARIF results.

const fs = require('fs');
const path = require('path');

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
  const tool = {
    driver: {
      name: 'jest',
      informationUri: 'https://jestjs.io/',
      rules: []
    }
  };

  const results = [];

  if (!jestJson || !Array.isArray(jestJson.testResults)) {
    return null;
  }

  for (const testFile of jestJson.testResults) {
    for (const assertion of testFile.assertionResults || []) {
      const status = assertion.status; // 'passed'|'failed'|'skipped'
      if (status === 'failed') {
        const message = (assertion.failureMessages || []).join('\n');
        results.push({
          ruleId: assertion.title || 'test-failure',
          level: 'error',
          message: { text: message },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: path.relative(process.cwd(), testFile.name) }
              }
            }
          ]
        });
      }
    }
  }

  runs.push({
    tool,
    results
  });

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
