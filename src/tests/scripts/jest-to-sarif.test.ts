// eslint-disable-next-line @typescript-eslint/no-unused-vars
// ts-expect-error
import { extractStackLocations, toSarif } from '../../../scripts/jest-to-sarif.js';

describe('jest-to-sarif script helpers', () => {
  test('extractStackLocations parses stack traces', () => {
    const msg = "Error: boom\n    at Object.<anonymous> (/Users/me/project/src/file.ts:10:5)\n    at /other/path.js:1:1";
    const locs = extractStackLocations(msg);
    expect(locs).toHaveLength(2);
    expect(locs[0].filePath).toBe('/Users/me/project/src/file.ts');
    expect(locs[0].line).toBe(10);
    expect(locs[0].col).toBe(5);
  });

  test('toSarif includes only failed assertions by default', () => {
    const jestJson = {
      testResults: [
        {
          name: '/path/to/test1.test.ts',
          assertionResults: [
            { title: 'fails', status: 'failed', failureMessages: ['Error\n at /project/src/broken.ts:5:3'], fullName: 'suite fails' },
            { title: 'passes', status: 'passed', failureMessages: [], fullName: 'suite passes' }
          ]
        }
      ]
    };

    const sarif = toSarif(jestJson, { includePassed: false, relativePaths: true });
    expect(sarif!.runs[0].results).toHaveLength(1);
    expect(sarif!.runs[0].tool.driver.rules).toHaveLength(1);
  });

  test('toSarif includes passed assertions when flag set', () => {
    const jestJson = {
      testResults: [
        {
          name: '/path/to/test1.test.ts',
          assertionResults: [
            { title: 'fails', status: 'failed', failureMessages: ['Error\n at /project/src/broken.ts:5:3'], fullName: 'suite fails' },
            { title: 'passes', status: 'passed', failureMessages: [], fullName: 'suite passes' }
          ]
        }
      ]
    };

    const sarif = toSarif(jestJson, { includePassed: true, relativePaths: true });
    expect(sarif!.runs[0].results).toHaveLength(2);
    expect(sarif!.runs[0].tool.driver.rules).toHaveLength(2);
  });
});

export {};
