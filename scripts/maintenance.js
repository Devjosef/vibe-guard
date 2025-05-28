#!/usr/bin/env node

const { execSync } = require('child_process');
const chalk = require('chalk');
const { program } = require('commander');

// Helper function to run commands safely
function runCommand(command, errorMessage, allowNonZero = false) {
  try {
    return execSync(command, { stdio: 'inherit' });
  } catch (error) {
    if (allowNonZero) {
      return; // Don't treat as error
    }
    console.error(chalk.red(`❌ ${errorMessage}`));
    console.error(error.message);
    process.exit(1);
  }
}

// Helper function to log with timestamps
function log(message, type = 'info') {
  const timestamp = new Date().toISOString();
  const colorMap = {
    info: chalk.blue,
    success: chalk.green,
    warning: chalk.yellow,
    error: chalk.red
  };
  const color = colorMap[type] || chalk.white;
  console.log(color(`[${timestamp}] ${message}`));
}

// Check for outdated packages
function checkOutdated() {
  log('🔍 Checking for outdated packages...');
  runCommand('npm outdated', 'Failed to check outdated packages', true);
  log('✅ Package check completed', 'success');
}

// Run security audit
function runAudit() {
  log('🔒 Running security audit...');
  runCommand('npm audit', 'Security audit failed', true);
  log('✅ Security audit completed', 'success');
}

// Fix security issues
function fixAudit() {
  log('🔧 Fixing security issues...');
  try {
    runCommand('npm audit fix', 'Failed to fix security issues', true);
    log('✅ Security fixes applied', 'success');
  } catch (error) {
    log('⚠️ Some security issues could not be fixed automatically', 'warning');
  }
}

// Update dependencies
function updateDependencies() {
  log('📦 Updating dependencies...');
  runCommand('npm update', 'Failed to update dependencies');
  log('✅ Dependencies updated', 'success');
}

// Build the project
function buildProject() {
  log('🏗️  Building project...');
  runCommand('npm run build', 'Build failed');
  log('✅ Build completed', 'success');
}

// Run tests
function runTests() {
  log('🧪 Running tests...');
  runCommand('npm test', 'Tests failed');
  log('✅ Tests passed', 'success');
}

// Full maintenance routine
function fullMaintenance() {
  log('🚀 Starting full maintenance routine...', 'info');
  
  checkOutdated();
  runAudit();
  fixAudit();
  updateDependencies();
  buildProject();
  runTests();
  
  log('✅ Maintenance completed successfully!', 'success');
}

// Setup CLI commands
program
  .name('maintenance')
  .description('Vibe-Guard maintenance script')
  .version('1.0.0');

program
  .command('check')
  .description('Check for outdated packages and security issues')
  .action(() => {
    checkOutdated();
    runAudit();
  });

program
  .command('update')
  .description('Update dependencies and fix security issues')
  .action(() => {
    updateDependencies();
    fixAudit();
    buildProject();
  });

program
  .command('full')
  .description('Run full maintenance routine')
  .action(fullMaintenance);

program.parse(); 