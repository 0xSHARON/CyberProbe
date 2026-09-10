import { runCyberProbeScan } from './scanner.js';

async function test() {
  console.log('Testing CyberProbe scanner on https://example.com ...');
  try {
    const result = await runCyberProbeScan('https://example.com', 'Quick Header Audit', (entry) => {
      console.log(`[STREAM ${entry.time}] [${entry.level}] ${entry.message}`);
    });
    console.log('Scan completed successfully!');
    console.log('Target Info:', result.targetInfo);
    console.log('Counts:', result.counts);
    console.log('Vulnerabilities found:', result.vulnerabilities.length);
    console.log('Security Headers checked:', Object.keys(result.securityHeaders));
  } catch (err) {
    console.error('Scan failed:', err);
  }
}

test();
