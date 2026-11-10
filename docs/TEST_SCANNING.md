# Test Scanning

Vibe-Guard uses GitHub Actions to type-check, lint, build, and run Jest tests. Scanner findings can be exported as SARIF with the CLI; Jest result conversion is a separate local utility.

## CI Pipeline

The test suite runs on Node.js 20 and 22 for:
- Every push to the `main` branch
- All pull requests targeting `main`

The workflow builds the project and runs the full Jest suite on every push to `main` and pull request targeting `main`.

## Local Testing

To convert Jest output to SARIF locally:

```bash
# Run tests and generate SARIF
npx jest --json --outputFile=jest-output.json
node scripts/jest-to-sarif.js jest-output.json test-results.sarif
```

The generated files (`jest-output.json` and `test-results.sarif`) are git-ignored by default.

Test status is available in the GitHub Actions run. To export source-code findings, run `vibe-guard scan . --format sarif --output-file security-report.sarif`.