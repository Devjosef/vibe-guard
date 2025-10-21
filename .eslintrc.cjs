module.exports = {
  root: true,
  parser: '@typescript-eslint/parser',
  parserOptions: {
    ecmaVersion: 2020,
    sourceType: 'module'
  },
  plugins: ['@typescript-eslint'],
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended',
    'prettier'
  ],
  env: {
    node: true,
    jest: true,
    es6: true
  },
  rules: {
    'no-unused-vars': 'off',
    '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],
    '@typescript-eslint/explicit-module-boundary-types': 'off',
    // Allow explicit any in places where typing would be invasive for now
    '@typescript-eslint/no-explicit-any': 'off',
    // Some regexes rely on escapes for clarity across engines; relax this rule
    'no-useless-escape': 'off',
    // Allow require() usage in a few cases (e.g., conditional or interop)
    '@typescript-eslint/no-var-requires': 'off'
  }

  ,
  // Override rules specifically for AST-heavy rule files where regexes,
  // special characters and dynamic typing are common and intentional.
  overrides: [
    {
      files: ['src/rules/**'],
      rules: {
        // Many rules are noisy in rule implementations because they
        // manipulate source text, regexes, or use `any` for AST nodes.
        'no-useless-escape': 'off',
        '@typescript-eslint/no-explicit-any': 'off',
        '@typescript-eslint/no-var-requires': 'off',
        'prefer-const': 'off',
        '@typescript-eslint/no-unused-vars': 'off'
      }
    }
  ]
};

