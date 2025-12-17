module.exports = {
  root: true,
  parser: '@typescript-eslint/parser',
  parserOptions: { ecmaVersion: 2020, sourceType: 'module' },
  plugins: ['@typescript-eslint'],
  extends: ['eslint:recommended', 'plugin:@typescript-eslint/recommended', 'prettier'],
  env: { node: true, jest: true, es6: true },
  rules: {
    'no-unused-vars': 'off',
    '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],
    '@typescript-eslint/explicit-module-boundary-types': 'off',
    '@typescript-eslint/no-explicit-any': 'off', // AST nodes in rules
    'no-useless-escape': 'off', // regex patterns in rules
    '@typescript-eslint/no-var-requires': 'off' // dynamic rule loading
  },
  overrides: [
    {
      files: ['src/rules/**'],
      rules: {
        'no-useless-escape': 'off', // regex-heavy rule files
        '@typescript-eslint/no-explicit-any': 'off', // AST manipulation
        '@typescript-eslint/no-var-requires': 'off',
        'prefer-const': 'off',
        '@typescript-eslint/no-unused-vars': 'off'
      }
    }
  ]
};
