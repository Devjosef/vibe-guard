# Test Scanning

Vibe-Guard uses GitHub Actions and SARIF reporting for comprehensive test analysis and security scanning. Our CI pipeline automatically runs tests and uploads results to GitHub's code scanning interface.

## CI Pipeline

Tests are automatically run on:
- Every push to the `main` branch
- All pull requests targeting `main`

The workflow:
1. Runs all Jest tests
2. Converts test results to SARIF format
3. Uploads results to GitHub's code scanning interface

## Local Testing

To run tests and generate SARIF locally:

```bash
# Run tests and generate SARIF
npx jest --json --outputFile=jest-output.json
node scripts/jest-to-sarif.js jest-output.json test-results.sarif
```

The generated files (`jest-output.json` and `test-results.sarif`) are git-ignored by default.

## Viewing Results

Test results can be viewed in two places:
1. GitHub Actions tab - Shows test execution and overall status
2. Security tab > Code scanning alerts - Shows detailed test analysis

## Permissions

The CI pipeline requires the following GitHub permissions:
- `security-events: write` - For uploading SARIF results
- `actions: read` - For running the workflow
- `contents: read` - For checking out code