module.exports = {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'type-enum': [
      2,
      'always',
      ['build', 'chore', 'ci', 'docs', 'feat', 'fix', 'perf', 'refactor', 'revert', 'style', 'test', 'feat!', 'fix!', 'refactor!'],
    ],
    // Enforce 100 character limit for header (subject line)
    'header-max-length': [2, 'always', 100],
    'subject-max-length': [2, 'always', 100],
    // Enforce conventional commit format
    'subject-case': [0], // Disabled - allows any case including UPPERCASE_VARS, camelCase, etc.
    'subject-empty': [2, 'never'],
    'subject-full-stop': [2, 'never', '.'],
    'type-case': [2, 'always', 'lower-case'], // Keep type lowercase (feat, fix, etc.)
    'type-empty': [2, 'never'],
  },
}
