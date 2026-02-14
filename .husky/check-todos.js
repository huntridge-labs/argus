#!/usr/bin/env node
/**
 * Cross-platform TODO and release-utils checker
 * Works on Windows, macOS, and Linux
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// Comment patterns for different file types
const commentPatterns = {
  py: '#',
  yml: '#',
  yaml: '#',
  toml: '#',
  tf: '#|//',
  md: '<!--',
  js: '//',
  ts: '//',
  sh: '#',
  bash: '#'
};

// ANSI color codes (work on most terminals including Windows Terminal)
const colors = {
  yellow: '\x1b[33m',
  reset: '\x1b[0m'
};

function getCommentPattern(ext) {
  return commentPatterns[ext] || '#|//|<!--';
}

function printWarning(message) {
  console.log(`${colors.yellow}${message}${colors.reset}`);
}

function getGitFiles() {
  try {
    const output = execSync('git ls-files', { encoding: 'utf8' });
    return output.trim().split('\n').filter(file => {
      // Exclude binary files, docs, and generated content
      const excludePatterns = [
        /^docs\//,
        /^backend\/notebooks\/images\//,
        /\.(jpg|jpeg|png|pdf|pyc)$/,
        /\.git\//,
        /node_modules\//
      ];
      return !excludePatterns.some(pattern => pattern.test(file));
    });
  } catch (error) {
    console.warn('Warning: Could not get git files list');
    return [];
  }
}

function searchInFile(filePath, pattern) {
  try {
    if (!fs.existsSync(filePath)) return [];

    const content = fs.readFileSync(filePath, 'utf8');
    const lines = content.split('\n');
    const matches = [];

    const regex = new RegExp(`(${pattern})\\s*TODO`, 'i');

    lines.forEach((line, index) => {
      if (regex.test(line)) {
        matches.push(`${index + 1}:${line.trim()}`);
      }
    });

    return matches;
  } catch (error) {
    return [];
  }
}

function checkTodos() {
  console.log('Running TODO checker...');

  const files = getGitFiles();
  const todos = [];
  const ignores = [];

  files.forEach(file => {
    const ext = path.extname(file).slice(1);
    const pattern = getCommentPattern(ext);

    // Check for TODOs
    const todoMatches = searchInFile(file, pattern);
    if (todoMatches.length > 0) {
      todos.push(`${file}: ${todoMatches.join(', ')}`);
    }

    // Check for release-utils ignore comments
    const ignorePattern = `(${pattern})\\s*release-utils:\\s*ignore`;
    try {
      const content = fs.readFileSync(file, 'utf8');
      const lines = content.split('\n');
      const regex = new RegExp(ignorePattern, 'i');

      lines.forEach((line, index) => {
        if (regex.test(line)) {
          ignores.push(`${file}:${index + 1}:${line.trim()}`);
        }
      });
    } catch (error) {
      // Ignore file read errors
    }
  });

  // Display results
  if (todos.length > 0) {
    printWarning('********** WARNING: TODO Check Failed **********');
    todos.forEach(todo => console.log(todo));
  }

  if (ignores.length > 0) {
    printWarning('********** WARNING: release-utils Ignore Check Failed **********');
    ignores.forEach(ignore => console.log(ignore));
  }
}

if (require.main === module) {
  checkTodos();
}

module.exports = { checkTodos };
