import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import importX from 'eslint-plugin-import-x';
import jsdoc from 'eslint-plugin-jsdoc';
import prettierRecommended from 'eslint-plugin-prettier/recommended';

// AST Contexts we want JSDoc enforced in
// Documentation for available ASTs can be found at https://github.com/estree/estree
const jsdocContexts = [
  'ClassDeclaration',
  'ClassExpression',
  'FunctionDeclaration',
  'FunctionExpression',
  'MethodDefinition',
];

export default tseslint.config(
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },

  { ignores: ['eslint.config.js', 'dist/**', 'node_modules/**'] },

  js.configs.recommended,
  importX.flatConfigs.typescript,

  // Strict, type-aware TypeScript rules
  ...tseslint.configs.strictTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,

  // TSDoc
  jsdoc.configs['flat/recommended-typescript-error'],

  // Force nice imports and docs
  {
    rules: {
      // Imports
      'sort-imports': [
        'error',
        {
          ignoreDeclarationSort: true,
        },
      ], // Sorts imports within an import line, declaration sort is disabled and handled in import-x/order which has type import support
      'import-x/order': [
        'error',
        {
          alphabetize: {
            order: 'asc',
            caseInsensitive: true,
            orderImportKind: 'asc',
          },
          'newlines-between': 'always',
        },
      ], // Sort import statements, grouped by type
      'import-x/no-extraneous-dependencies': [
        'error',
        { devDependencies: true },
      ], // Don't allow imports from packages that aren't in dependencies or dev dependencies
      'import-x/consistent-type-specifier-style': ['error', 'prefer-top-level'], // Types must be imported with `import type { TYPE_A, TYPE_B} from 'module'`
      'import-x/exports-last': 'error', // Exports must be done at end of file
      'import-x/group-exports': 'error', // Exports must be grouped in a single declaration

      // JSDoc
      'jsdoc/require-jsdoc': [
        'error',
        {
          contexts: jsdocContexts,
        },
      ], // JSDoc must be present on specified contexts
      'jsdoc/require-description': [
        'error',
        {
          contexts: jsdocContexts,
        },
      ], // JSDoc must have description on specified contexts

      // Enforce type import/export
      '@typescript-eslint/consistent-type-imports': 'error', // Importing types must be done with import type
      '@typescript-eslint/consistent-type-exports': 'error', // Exporting types must be done with export type
      '@typescript-eslint/consistent-type-definitions': ['error', 'type'],
    },
  },

  // Prettier
  prettierRecommended,
);
