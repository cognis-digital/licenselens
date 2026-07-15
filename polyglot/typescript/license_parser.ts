import { LicenseExpression } from './license_expression';
import { LicenseParser } from './license_parser';
import { LicenseResolver } from './license_resolver';
import { LicenseResult } from './license_result';

// =============================================================================
// RUNNABLE DEMO / ENTRY POINT
// =============================================================================

const parser = new LicenseParser();
const resolver = new LicenseResolver();

function demo() {
  const testCases: [string, string][] = [
    ['MIT', 'MIT'],
    ['Apache-2.0', 'Apache-2.0'],
    ['MIT OR Apache-2.0', 'MIT || Apache-2.0'],
    ['GPL-3.0+', 'GPL-3.0+'],
    ['MIT AND (Apache-2.0 OR GPL-3.0)', 'MIT && (Apache-2.0 || GPL-3.0)'],
    ['MIT; Apache-2.0', 'MIT; Apache-2.0'],
  ];

  console.log('=== LICENSELENS: License Parser Demo ===\n');

  for (const [input, expected] of testCases) {
    const result = parser.parse(input);
    const resolved = resolver.resolve(result.expression);
    const status = resolved.canonical === expected ? '✓' : `⚠ (got ${resolved.canonical})`;
    console.log(`${status} "${input}" → ${resolved.canonical}`);
  }

  // Show AST structure
  console.log('\n=== AST Structure Example ===');
  const ast = parser.parse('MIT OR Apache-2.0');
  console.log(JSON.stringify(ast, null, 2));
}

demo();