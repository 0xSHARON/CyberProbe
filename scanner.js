import tls from 'tls';
import dns from 'dns/promises';
import { URL } from 'url';

/**
 * CyberProbe Real Security Scanning Engine
 * Performs non-invasive, passive, and defensive security auditing:
 * - Real HTTP Security Headers Audit (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, CORS)
 * - Real SSL/TLS Certificate Analysis (Cipher suite, TLS version, validity days, issuer, SAN)
 * - Real DNS & Host Information (IPv4/IPv6, MX records, SPF/DMARC TXT records)
 * - Real Information Disclosure Audit (Server banners, X-Powered-By, Git exposure, sensitive endpoints)
 * - Real Cookie Security Flags (Secure, HttpOnly, SameSite)
 * - Real OWASP 2024 Category & CWE Mapping with exact Remediation Code Snippets
 */

// Helper to format timestamps for the live probe terminal
function getLogTime() {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, '0');
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

export async function runCyberProbeScan(targetInput, scanProfile = 'Full Pen-Test', logCallback = () => {}) {
  const startTime = Date.now();
  const logs = [];

  const emitLog = (level, message) => {
    const entry = {
      time: getLogTime(),
      level: level.toUpperCase(), // 'INFO', 'WARN', 'CRIT', 'PASS'
      message
    };
    logs.push(entry);
    logCallback(entry);
  };

  // Normalize URL
  let targetUrlStr = targetInput.trim();
  if (!/^https?:\/\//i.test(targetUrlStr)) {
    targetUrlStr = 'https://' + targetUrlStr;
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(targetUrlStr);
  } catch (err) {
    throw new Error(`Invalid target URL: ${targetInput}`);
  }

  const hostname = parsedUrl.hostname;
  const isHttps = parsedUrl.protocol === 'https:';
  const port = parsedUrl.port || (isHttps ? 443 : 80);

  emitLog('INFO', `Starting scan on ${targetUrlStr}`);
  emitLog('INFO', `Resolved protocol: ${parsedUrl.protocol}, target host: ${hostname}, port: ${port}`);
  emitLog('INFO', `Selected scan profile: [${scanProfile}]`);

  const vulnerabilities = [];
  const securityHeaders = {
    'Content-Security-Policy': { status: 'Missing', value: null, severity: 'Critical' },
    'Strict-Transport-Security': { status: 'Missing', value: null, severity: 'High' },
    'X-Frame-Options': { status: 'Missing', value: null, severity: 'High' },
    'X-Content-Type-Options': { status: 'Missing', value: null, severity: 'Medium' },
    'Referrer-Policy': { status: 'Not Set', value: null, severity: 'Low' },
    'Permissions-Policy': { status: 'Missing', value: null, severity: 'Medium' },
  };

  const targetInfo = {
    targetUrl: targetUrlStr,
    hostname,
    scanType: scanProfile,
    startTime: new Date().toLocaleString(),
    duration: '0s',
    discoveredUrls: 1,
    technologies: [],
    ipAddresses: [],
    tlsInfo: null,
    dnsInfo: null,
    statusCode: null,
    riskScore: 0,
    status: 'Running'
  };

  // 1. DNS & Network Resolution
  emitLog('INFO', `Querying DNS infrastructure for ${hostname}...`);
  let hasDmarc = false;
  try {
    const addresses = await dns.resolve4(hostname).catch(() => []);
    const ipv6Addresses = await dns.resolve6(hostname).catch(() => []);
    const cnameRecords = await dns.resolveCname(hostname).catch(() => []);
    targetInfo.ipAddresses = [...addresses, ...ipv6Addresses];
    if (targetInfo.ipAddresses.length > 0) {
      emitLog('PASS', `DNS records resolved: ${targetInfo.ipAddresses.join(', ')}`);
    } else {
      emitLog('WARN', `Could not resolve IP records directly.`);
    }

    // MX Records & SPF / DMARC
    const mxRecords = await dns.resolveMx(hostname).catch(() => []);
    const txtRecords = await dns.resolveTxt(hostname).catch(() => []);
    const txtFlat = txtRecords.map(r => r.join(''));
    const hasSpf = txtFlat.some(t => t.toLowerCase().includes('v=spf1'));
    const dmarcRecords = await dns.resolveTxt(`_dmarc.${hostname}`).catch(() => []);
    hasDmarc = dmarcRecords.some(r => r.join('').toLowerCase().includes('v=dmarc1'));

    targetInfo.dnsInfo = {
      ipAddresses: addresses,
      ipv6: ipv6Addresses,
      cname: cnameRecords,
      mxRecords: mxRecords.map(m => `${m.exchange} (prio: ${m.priority})`),
      hasSpf,
      hasDmarc
    };

    if (!hasDmarc) {
      vulnerabilities.push({
        id: 'DNS-01',
        name: 'Missing DMARC Email Security Record',
        severity: 'Low',
        category: 'A05:2021-Security Misconfiguration',
        cwe: 'CWE-358',
        endpoint: `_dmarc.${hostname}`,
        status: 'Open',
        description: 'Domain lacks a DMARC policy record, increasing the risk of email spoofing and phishing leveraging your domain name.',
        evidence: 'No TXT record found at _dmarc.' + hostname,
        impact: 'Attackers can spoof emails appearing to originate from your domain, harming reputation.',
        remediation: {
          summary: 'Publish a TXT record for _dmarc.' + hostname + ' with p=reject or p=quarantine.',
          codeSnippet: `_dmarc.${hostname} IN TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@${hostname}; pct=100"`
        }
      });
      emitLog('WARN', `DMARC record missing on _dmarc.${hostname}`);
    } else {
      emitLog('PASS', `DMARC email authentication record verified.`);
    }
  } catch (err) {
    emitLog('WARN', `DNS inspection notice: ${err.message}`);
  }

  // 2. SSL/TLS Handshake & Certificate Verification (if HTTPS)
  if (isHttps) {
    emitLog('INFO', `Initiating TLS handshake with ${hostname}:${port}...`);
    try {
      const tlsInfo = await new Promise((resolve, reject) => {
        const socket = tls.connect(
          {
            host: hostname,
            port: Number(port),
            servername: hostname,
            rejectUnauthorized: false, // passive inspection: we inspect even self-signed/invalid
            timeout: 5000
          },
          () => {
            const cert = socket.getPeerCertificate(true);
            const cipher = socket.getCipher();
            const protocol = socket.getProtocol();
            const authorized = socket.authorized;
            const authError = socket.authorizationError;

            socket.end();
            resolve({
              protocol,
              cipherName: cipher?.name,
              cipherStandard: cipher?.standardName || cipher?.name,
              cipherVersion: cipher?.version,
              subject: cert?.subject,
              issuer: cert?.issuer,
              validFrom: cert?.valid_from,
              validTo: cert?.valid_to,
              daysRemaining: cert?.valid_to ? Math.round((new Date(cert.valid_to) - new Date()) / (1000 * 60 * 60 * 24)) : null,
              san: cert?.subjectaltname,
              authorized,
              authError
            });
          }
        );

        socket.on('error', (e) => reject(e));
        socket.on('timeout', () => {
          socket.destroy();
          reject(new Error('TLS connection timed out after 5000ms'));
        });
      });

      targetInfo.tlsInfo = tlsInfo;
      emitLog('PASS', `TLS Handshake successful: ${tlsInfo.protocol} (${tlsInfo.cipherName})`);
      emitLog('INFO', `Certificate Issuer: ${tlsInfo.issuer?.O || tlsInfo.issuer?.CN || 'Unknown'} (Expires in ${tlsInfo.daysRemaining} days)`);

      if (tlsInfo.daysRemaining !== null && tlsInfo.daysRemaining <= 15) {
        vulnerabilities.push({
          id: 'TLS-EXP',
          name: 'SSL/TLS Certificate Expiring Soon',
          severity: tlsInfo.daysRemaining <= 0 ? 'Critical' : 'High',
          category: 'A02:2021-Cryptographic Failures',
          cwe: 'CWE-298',
          endpoint: `${hostname}:${port}`,
          status: 'Open',
          description: `The SSL/TLS certificate expires in ${tlsInfo.daysRemaining} days (${tlsInfo.validTo}).`,
          evidence: `Issuer: ${tlsInfo.issuer?.CN || tlsInfo.issuer?.O}, Valid until: ${tlsInfo.validTo}`,
          impact: 'Visitors will receive severe browser security warning pages blocking access.',
          remediation: {
            summary: 'Renew the SSL/TLS certificate immediately using ACME/Certbot or your CA.',
            codeSnippet: `# Certbot renewal command\nsudo certbot renew --force-renewal`
          }
        });
        emitLog('CRIT', `TLS Certificate is expiring soon or expired (${tlsInfo.daysRemaining} days left)!`);
      }

      if (!tlsInfo.authorized) {
        vulnerabilities.push({
          id: 'TLS-AUTH',
          name: 'Untrusted or Invalid SSL/TLS Certificate',
          severity: 'Critical',
          category: 'A02:2021-Cryptographic Failures',
          cwe: 'CWE-295',
          endpoint: `${hostname}:${port}`,
          status: 'Open',
          description: `The certificate is not trusted by public CAs: ${tlsInfo.authError || 'Self-signed or hostname mismatch'}.`,
          evidence: `Authorization Error: ${tlsInfo.authError}`,
          impact: 'Users encounter TLS security blocks; susceptible to Man-In-The-Middle (MITM) attacks.',
          remediation: {
            summary: 'Install a certificate issued by a recognized Certificate Authority (e.g., Let\'s Encrypt).',
            codeSnippet: `sudo certbot --nginx -d ${hostname}`
          }
        });
        emitLog('CRIT', `TLS Authorization failure: ${tlsInfo.authError}`);
      }
    } catch (err) {
      emitLog('WARN', `TLS Handshake error: ${err.message}`);
    }
  } else {
    emitLog('CRIT', `Target uses unencrypted HTTP protocol!`);
    vulnerabilities.push({
      id: 'HTTP-PLAINTEXT',
      name: 'Cleartext Transmission of Sensitive Data (Unencrypted HTTP)',
      severity: 'Critical',
      category: 'A02:2021-Cryptographic Failures',
      cwe: 'CWE-319',
      endpoint: targetUrlStr,
      status: 'Open',
      description: 'The target website communicates over plain HTTP without TLS encryption. All communications, credentials, and session tokens can be intercepted.',
      evidence: `Protocol: http://`,
      impact: 'Eavesdropping, credential theft, and traffic injection by intermediaries on the network.',
      remediation: {
        summary: 'Enforce HTTPS on port 443 with automated TLS certificates and redirect all HTTP traffic.',
        codeSnippet: `# Nginx HTTP to HTTPS redirect\nserver {\n    listen 80;\n    server_name ${hostname};\n    return 301 https://$host$request_uri;\n}`
      }
    });
  }

  // 3. Real HTTP Request & Response Headers Audit
  emitLog('INFO', `Dispatching probing HTTP request to ${targetUrlStr}...`);
  let responseHeaders = {};
  let rawHeadersObj = {};
  let responseBodyText = '';

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000);

    const response = await fetch(targetUrlStr, {
      method: 'GET',
      signal: controller.signal,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 CyberProbe/2.5',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5'
      }
    });
    clearTimeout(timeoutId);

    targetInfo.statusCode = response.status;
    emitLog('PASS', `HTTP Response received: Status ${response.status} ${response.statusText}`);

    // Collect headers (case-insensitive)
    for (const [key, value] of response.headers.entries()) {
      responseHeaders[key.toLowerCase()] = value;
      rawHeadersObj[key] = value;
    }

    try {
      responseBodyText = await response.text();
    } catch (e) {
      responseBodyText = '';
    }
  } catch (fetchErr) {
    emitLog('WARN', `Direct probe encountered an issue: ${fetchErr.message}. Attempting fallback probe...`);
    // Fallback: Attempt simple HEAD
    try {
      const fbResp = await fetch(targetUrlStr, { method: 'HEAD' });
      targetInfo.statusCode = fbResp.status;
      for (const [key, value] of fbResp.headers.entries()) {
        responseHeaders[key.toLowerCase()] = value;
        rawHeadersObj[key] = value;
      }
      emitLog('PASS', `Fallback probe succeeded with status ${fbResp.status}`);
    } catch (err2) {
      emitLog('CRIT', `Target unreachable: ${err2.message}`);
      vulnerabilities.push({
        id: 'CONN-FAIL',
        name: 'Target Host Unreachable or Connection Refused',
        severity: 'High',
        category: 'A05:2021-Security Misconfiguration',
        cwe: 'CWE-400',
        endpoint: targetUrlStr,
        status: 'Open',
        description: `CyberProbe could not establish an HTTP connection: ${err2.message}. Verify firewall, DNS, and service status.`,
        evidence: err2.message,
        impact: 'Service disruption or target blocked inspection.',
        remediation: {
          summary: 'Ensure port 80/443 is open and server is accepting external HTTP/HTTPS connections.',
          codeSnippet: `curl -Iv ${targetUrlStr}`
        }
      });
    }
  }

  // 4. Detailed Security Headers Analysis
  emitLog('INFO', `Auditing HTTP Security Headers...`);

  // (A) Content-Security-Policy (CSP)
  const csp = responseHeaders['content-security-policy'];
  if (!csp) {
    securityHeaders['Content-Security-Policy'] = { status: 'Missing', value: null, severity: 'Critical' };
    vulnerabilities.push({
      id: 'SEC-CSP-MISSING',
      name: 'Missing Content-Security-Policy (CSP)',
      severity: 'Critical',
      category: 'A05:2021-Security Misconfiguration',
      cwe: 'CWE-693',
      endpoint: '/',
      status: 'Open',
      description: 'Content-Security-Policy (CSP) header is absent. Without a CSP, the browser has no restrictions against inline script execution, unauthorized script inclusion, or Cross-Site Scripting (XSS) exploitation.',
      evidence: 'Header "Content-Security-Policy" not returned by server.',
      impact: 'High susceptibility to stored, reflected, and DOM-based Cross-Site Scripting (XSS) and data exfiltration.',
      remediation: {
        summary: 'Implement a strict CSP policy that disables inline scripts and specifies trusted source origins.',
        codeSnippet: `# Nginx\nadd_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';" always;\n\n# Express.js (helmet)\napp.use(helmet.contentSecurityPolicy());`
      }
    });
    emitLog('CRIT', `Missing Content-Security-Policy (CSP) header!`);
  } else {
    securityHeaders['Content-Security-Policy'] = { status: 'Present', value: csp, severity: 'Pass' };
    emitLog('PASS', `Content-Security-Policy detected.`);
    // Audit CSP directives
    if (csp.includes("'unsafe-inline'") || csp.includes("'unsafe-eval'")) {
      vulnerabilities.push({
        id: 'SEC-CSP-UNSAFE',
        name: 'Weak Content-Security-Policy (unsafe-inline / unsafe-eval detected)',
        severity: 'Medium',
        category: 'A05:2021-Security Misconfiguration',
        cwe: 'CWE-693',
        endpoint: '/',
        status: 'Open',
        description: 'The Content-Security-Policy contains \'unsafe-inline\' or \'unsafe-eval\', which negates much of the XSS protection provided by CSP.',
        evidence: `CSP directive value: ${csp.substring(0, 120)}...`,
        impact: 'Permits injection of inline JavaScript elements if user input is reflected into HTML.',
        remediation: {
          summary: 'Use cryptographic nonces (nonce-...) or SHA-256 hashes instead of unsafe-inline.',
          codeSnippet: `Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-rAnd0m123';`
        }
      });
      emitLog('WARN', `CSP contains unsafe-inline or unsafe-eval`);
    }
  }

  // (B) Strict-Transport-Security (HSTS)
  const hsts = responseHeaders['strict-transport-security'];
  if (isHttps) {
    if (!hsts) {
      securityHeaders['Strict-Transport-Security'] = { status: 'Missing', value: null, severity: 'High' };
      vulnerabilities.push({
        id: 'SEC-HSTS-MISSING',
        name: 'Missing HTTP Strict-Transport-Security (HSTS)',
        severity: 'High',
        category: 'A05:2021-Security Misconfiguration',
        cwe: 'CWE-319',
        endpoint: '/',
        status: 'Open',
        description: 'HSTS instructs modern browsers to exclusively connect via HTTPS, preventing SSL stripping and downgrade attacks.',
        evidence: 'Header "Strict-Transport-Security" not returned.',
        impact: 'Users making an initial HTTP connection can have their traffic intercepted or downgraded to cleartext.',
        remediation: {
          summary: 'Add Strict-Transport-Security with a max-age of at least 1 year (31536000 seconds) and includeSubDomains.',
          codeSnippet: `# Nginx\nadd_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;\n\n# Apache\nHeader always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"`
        }
      });
      emitLog('WARN', `Missing Strict-Transport-Security (HSTS) header!`);
    } else {
      securityHeaders['Strict-Transport-Security'] = { status: 'Present', value: hsts, severity: 'Pass' };
      emitLog('PASS', `Strict-Transport-Security present: ${hsts}`);
    }
  }

  // (C) X-Frame-Options
  const xfo = responseHeaders['x-frame-options'];
  if (!xfo && (!csp || !csp.includes('frame-ancestors'))) {
    securityHeaders['X-Frame-Options'] = { status: 'Missing', value: null, severity: 'High' };
    vulnerabilities.push({
      id: 'SEC-XFO-MISSING',
      name: 'Missing Anti-Clickjacking Defense (X-Frame-Options / frame-ancestors)',
      severity: 'High',
      category: 'A05:2021-Security Misconfiguration',
      cwe: 'CWE-1021',
      endpoint: '/',
      status: 'Open',
      description: 'Target site does not set X-Frame-Options or frame-ancestors. Attackers can embed this website inside an invisible <iframe> on a malicious domain to trick authenticated users into clicking buttons or submitting forms.',
      evidence: 'Neither "X-Frame-Options" nor "frame-ancestors" policy header was received.',
      impact: 'Clickjacking (UI redressing) attacks allowing unauthorized state changes or keystroke interception.',
      remediation: {
        summary: 'Set X-Frame-Options to DENY or SAMEORIGIN, or configure frame-ancestors in CSP.',
        codeSnippet: `# Nginx\nadd_header X-Frame-Options "DENY" always;\n\n# Express.js\napp.use((req, res, next) => {\n  res.setHeader('X-Frame-Options', 'DENY');\n  next();\n});`
      }
    });
    emitLog('WARN', `Missing X-Frame-Options anti-clickjacking header!`);
  } else {
    securityHeaders['X-Frame-Options'] = { status: 'Present', value: xfo || 'Protected via CSP frame-ancestors', severity: 'Pass' };
    emitLog('PASS', `Clickjacking protection active (${xfo || 'CSP frame-ancestors'}).`);
  }

  // (D) X-Content-Type-Options
  const xcto = responseHeaders['x-content-type-options'];
  if (!xcto || !xcto.toLowerCase().includes('nosniff')) {
    securityHeaders['X-Content-Type-Options'] = { status: 'Missing', value: xcto || null, severity: 'Medium' };
    vulnerabilities.push({
      id: 'SEC-XCTO-MISSING',
      name: 'Missing X-Content-Type-Options (MIME-Type Sniffing Protection)',
      severity: 'Medium',
      category: 'A05:2021-Security Misconfiguration',
      cwe: 'CWE-693',
      endpoint: '/',
      status: 'Open',
      description: 'Without X-Content-Type-Options: nosniff, older or vulnerable browsers may interpret user-uploaded files or responses as executable JavaScript regardless of the declared Content-Type.',
      evidence: `Received: ${xcto || 'Header absent'}`,
      impact: 'MIME confusion attacks allowing stored XSS via file uploads or non-script resources.',
      remediation: {
        summary: 'Enforce nosniff for all HTTP responses.',
        codeSnippet: `# Nginx\nadd_header X-Content-Type-Options "nosniff" always;\n\n# Apache\nHeader always set X-Content-Type-Options "nosniff"`
      }
    });
    emitLog('WARN', `Missing X-Content-Type-Options: nosniff`);
  } else {
    securityHeaders['X-Content-Type-Options'] = { status: 'Present', value: xcto, severity: 'Pass' };
    emitLog('PASS', `X-Content-Type-Options set to nosniff.`);
  }

  // (E) Referrer-Policy
  const refPol = responseHeaders['referrer-policy'];
  if (!refPol) {
    securityHeaders['Referrer-Policy'] = { status: 'Not Set', value: null, severity: 'Low' };
    vulnerabilities.push({
      id: 'SEC-REFPOL-MISSING',
      name: 'Referrer-Policy Header Not Enforced',
      severity: 'Low',
      category: 'A05:2021-Security Misconfiguration',
      cwe: 'CWE-200',
      endpoint: '/',
      status: 'Open',
      description: 'The Referrer-Policy header controls how much referrer information (including query parameters, tokens, or internal URLs) is sent to external sites when navigating or loading resources.',
      evidence: 'Header "Referrer-Policy" not found in server response.',
      impact: 'Potential leakage of sensitive query strings, session IDs, or private internal URLs to external third-party servers.',
      remediation: {
        summary: 'Enforce strict-origin-when-cross-origin or no-referrer.',
        codeSnippet: `# Nginx\nadd_header Referrer-Policy "strict-origin-when-cross-origin" always;`
      }
    });
    emitLog('WARN', `Referrer-Policy not explicitly set`);
  } else {
    securityHeaders['Referrer-Policy'] = { status: 'Present', value: refPol, severity: 'Pass' };
    emitLog('PASS', `Referrer-Policy set to ${refPol}`);
  }

  // (F) Permissions-Policy
  const permPol = responseHeaders['permissions-policy'] || responseHeaders['feature-policy'];
  if (!permPol) {
    securityHeaders['Permissions-Policy'] = { status: 'Missing', value: null, severity: 'Medium' };
    vulnerabilities.push({
      id: 'SEC-PERMPOL-MISSING',
      name: 'Missing Permissions-Policy (Feature Policy)',
      severity: 'Medium',
      category: 'A05:2021-Security Misconfiguration',
      cwe: 'CWE-693',
      endpoint: '/',
      status: 'Open',
      description: 'Permissions-Policy allows developers to selectively enable or disable powerful browser features (camera, microphone, geolocation, payment APIs, accelerometer) for the current document and embedded frames.',
      evidence: 'Permissions-Policy header is missing.',
      impact: 'Embedded third-party scripts or iframes may request or abuse sensitive hardware sensors or capabilities.',
      remediation: {
        summary: 'Define a Permissions-Policy restricting sensitive browser hardware features.',
        codeSnippet: `add_header Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=()" always;`
      }
    });
    emitLog('WARN', `Missing Permissions-Policy header`);
  } else {
    securityHeaders['Permissions-Policy'] = { status: 'Present', value: permPol, severity: 'Pass' };
    emitLog('PASS', `Permissions-Policy active: ${permPol}`);
  }

  // (G) Cross-Origin Resource Sharing (CORS) check
  const acao = responseHeaders['access-control-allow-origin'];
  const acac = responseHeaders['access-control-allow-credentials'];
  if (acao === '*' && acac === 'true') {
    vulnerabilities.push({
      id: 'CORS-WILDCARD-CREDS',
      name: 'Critically Permissive CORS with Credentials Allowed',
      severity: 'Critical',
      category: 'A01:2021-Broken Access Control',
      cwe: 'CWE-942',
      endpoint: '/api/*',
      status: 'Open',
      description: 'Access-Control-Allow-Origin is set to wildcard (*) while Access-Control-Allow-Credentials is true, or origin reflection is improperly configured.',
      evidence: `Access-Control-Allow-Origin: ${acao}, Access-Control-Allow-Credentials: ${acac}`,
      impact: 'Any malicious website can perform authenticated API requests on behalf of victims and read back confidential data.',
      remediation: {
        summary: 'Specify an explicit, validated list of allowed trusted origins. Never mirror the Origin header without strict origin validation.',
        codeSnippet: `// Express CORS example\nconst allowed = ['https://trusted.com'];\napp.use(cors({ origin: allowed, credentials: true }));`
      }
    });
    emitLog('CRIT', `Overly permissive CORS configuration detected!`);
  } else if (acao === '*') {
    emitLog('INFO', `CORS Access-Control-Allow-Origin set to wildcard (*) for public resources.`);
  }

  // (H) Server & Technology Information Disclosure
  const serverHeader = responseHeaders['server'];
  const xPoweredBy = responseHeaders['x-powered-by'];
  const technologies = [];

  if (serverHeader) {
    technologies.push(serverHeader);
    if (/(\d+\.\d+)/.test(serverHeader)) {
      vulnerabilities.push({
        id: 'INFO-SERVER-VERSION',
        name: 'Server Banner Version Disclosure',
        severity: 'Low',
        category: 'A05:2021-Security Misconfiguration',
        cwe: 'CWE-200',
        endpoint: '/',
        status: 'Open',
        description: `Server header exposes exact software name and version: "${serverHeader}".`,
        evidence: `Server: ${serverHeader}`,
        impact: 'Facilitates targeted vulnerability exploits by allowing adversaries to pinpoint specific CVEs associated with the exposed version.',
        remediation: {
          summary: 'Configure server to suppress or obfuscate version banners.',
          codeSnippet: `# Nginx\nserver_tokens off;\n\n# Apache\nServerTokens Prod\nServerSignature Off`
        }
      });
      emitLog('WARN', `Server header exposes version: ${serverHeader}`);
    } else {
      emitLog('INFO', `Server banner detected: ${serverHeader}`);
    }
  }

  if (xPoweredBy) {
    technologies.push(xPoweredBy);
    vulnerabilities.push({
      id: 'INFO-POWERED-BY',
      name: 'Technology Disclosure via X-Powered-By Header',
      severity: 'Low',
      category: 'A05:2021-Security Misconfiguration',
      cwe: 'CWE-200',
      endpoint: '/',
      status: 'Open',
      description: `Target exposes backend technology stack via X-Powered-By header: "${xPoweredBy}".`,
      evidence: `X-Powered-By: ${xPoweredBy}`,
      impact: 'Discloses framework signatures assisting attackers in tailoring exploits.',
      remediation: {
        summary: 'Disable X-Powered-By header in application code or reverse proxy.',
        codeSnippet: `// Express.js\napp.disable('x-powered-by');\n\n// PHP php.ini\nexpose_php = Off`
      }
    });
    emitLog('WARN', `X-Powered-By header detected: ${xPoweredBy}`);
  }

  // Detect CDN / Cloud proxies
  if (responseHeaders['cf-ray'] || responseHeaders['server']?.toLowerCase().includes('cloudflare')) {
    technologies.push('Cloudflare CDN / WAF');
  }
  if (responseHeaders['x-amz-cf-id'] || responseHeaders['via']?.toLowerCase().includes('cloudfront')) {
    technologies.push('AWS CloudFront');
  }
  if (responseHeaders['x-varnish']) {
    technologies.push('Varnish Cache');
  }
  if (responseHeaders['x-github-request-id']) {
    technologies.push('GitHub Pages / Infrastructure');
  }

  // Check HTML body for frontend libraries
  if (responseBodyText) {
    if (responseBodyText.includes('wp-content') || responseBodyText.includes('wp-includes')) {
      technologies.push('WordPress CMS');
    }
    if (responseBodyText.includes('__NEXT_DATA__')) {
      technologies.push('Next.js');
    }
    if (responseBodyText.includes('react') || responseBodyText.includes('react-dom')) {
      technologies.push('React');
    }
    if (responseBodyText.includes('vue') || responseBodyText.includes('v-bind')) {
      technologies.push('Vue.js');
    }
  }

  targetInfo.technologies = Array.from(new Set(technologies));
  if (targetInfo.technologies.length === 0) {
    targetInfo.technologies = ['Modern Web Server (Custom/Masked)'];
  }
  emitLog('INFO', `Detected stack technologies: ${targetInfo.technologies.join(', ')}`);

  // (I) Cookies Security Audit
  const rawSetCookie = responseHeaders['set-cookie'];
  if (rawSetCookie) {
    const cookiesList = Array.isArray(rawSetCookie) ? rawSetCookie : [rawSetCookie];
    for (const cookieStr of cookiesList) {
      const cookieName = cookieStr.split('=')[0]?.trim() || 'SessionCookie';
      const isSecure = /;\s*secure/i.test(cookieStr);
      const isHttpOnly = /;\s*httponly/i.test(cookieStr);
      const hasSameSite = /;\s*samesite=/i.test(cookieStr);

      if (!isHttpOnly) {
        vulnerabilities.push({
          id: `COOKIE-HTTPONLY-${cookieName}`,
          name: `Cookie Missing HttpOnly Flag (${cookieName})`,
          severity: 'Medium',
          category: 'A05:2021-Security Misconfiguration',
          cwe: 'CWE-1004',
          endpoint: '/',
          status: 'Open',
          description: `Cookie "${cookieName}" was issued without the HttpOnly attribute. Accessible via document.cookie by client-side JavaScript.`,
          evidence: `Set-Cookie: ${cookieStr.substring(0, 80)}`,
          impact: 'If any XSS flaw exists on the application, attackers can harvest this cookie and hijack the user session.',
          remediation: {
            summary: 'Set the HttpOnly flag on all sensitive and session cookies.',
            codeSnippet: `Set-Cookie: ${cookieName}=...; Secure; HttpOnly; SameSite=Lax; Path=/`
          }
        });
        emitLog('WARN', `Cookie ${cookieName} missing HttpOnly flag`);
      }

      if (isHttps && !isSecure) {
        vulnerabilities.push({
          id: `COOKIE-SECURE-${cookieName}`,
          name: `Cookie Missing Secure Flag (${cookieName})`,
          severity: 'Medium',
          category: 'A05:2021-Security Misconfiguration',
          cwe: 'CWE-614',
          endpoint: '/',
          status: 'Open',
          description: `Cookie "${cookieName}" lacks the Secure attribute on an HTTPS domain.`,
          evidence: `Set-Cookie: ${cookieStr.substring(0, 80)}`,
          impact: 'Cookie can be inadvertently transmitted over unencrypted HTTP connections.',
          remediation: {
            summary: 'Enforce the Secure attribute on all cookies transmitted over HTTPS.',
            codeSnippet: `Set-Cookie: ${cookieName}=...; Secure; HttpOnly; SameSite=Lax; Path=/`
          }
        });
        emitLog('WARN', `Cookie ${cookieName} missing Secure flag`);
      }
    }
  }

  // 5. Diagnostic & Endpoint Surface Discovery (Passive & RFC Standard Checks)
  emitLog('INFO', `Probing standard security endpoints and metadata assets...`);
  const safeEndpoints = [
    { path: '/.well-known/security.txt', name: 'Security.txt Disclosure (RFC 9116)', required: true },
    { path: '/robots.txt', name: 'Robots.txt Crawler Rules', required: false },
    { path: '/.git/HEAD', name: 'Publicly Accessible .git Directory', criticalIfFound: true },
    { path: '/.env', name: 'Publicly Accessible Environment File (.env)', criticalIfFound: true }
  ];

  let discoveredCount = 1;

  for (const ep of safeEndpoints) {
    try {
      const probeUrl = new URL(ep.path, targetUrlStr).toString();
      const epResp = await fetch(probeUrl, {
        method: 'GET',
        headers: { 'User-Agent': 'CyberProbe-Diagnostic/2.5' }
      });

      if (epResp.ok) {
        discoveredCount++;
        const epBody = await epResp.text();

        if (ep.criticalIfFound && (epBody.includes('ref: refs/') || epBody.includes('DB_') || epBody.includes('API_KEY'))) {
          vulnerabilities.push({
            id: `LEAK-${ep.path.replace(/[^a-zA-Z0-9]/g, '_')}`,
            name: `Critical Data Exposure: ${ep.name}`,
            severity: 'Critical',
            category: 'A01:2021-Broken Access Control',
            cwe: 'CWE-538',
            endpoint: ep.path,
            status: 'Open',
            description: `A sensitive configuration or repository directory was found publicly accessible at ${ep.path}. Contains raw secrets, code commits, or environmental variables.`,
            evidence: `Endpoint ${ep.path} returned HTTP 200 with content matching sensitive source files.`,
            impact: 'Complete compromise of application source code, API keys, database credentials, or internal systems.',
            remediation: {
              summary: `Block public HTTP access to ${ep.path} in web server configuration immediately.`,
              codeSnippet: `# Nginx\nlocation ~ /\\.(git|env|svn) {\n    deny all;\n    return 404;\n}`
            }
          });
          emitLog('CRIT', `CRITICAL EXPOSURE DETECTED: ${ep.path} is publicly accessible!`);
        } else if (ep.path === '/.well-known/security.txt') {
          emitLog('PASS', `Security contact found at /.well-known/security.txt`);
        } else if (ep.path === '/robots.txt') {
          emitLog('INFO', `Discovered /robots.txt`);
        }
      } else {
        if (ep.path === '/.well-known/security.txt') {
          vulnerabilities.push({
            id: 'RFC9116-SECURITY-TXT',
            name: 'Missing /.well-known/security.txt (RFC 9116)',
            severity: 'Low',
            category: 'A05:2021-Security Misconfiguration',
            cwe: 'CWE-1059',
            endpoint: '/.well-known/security.txt',
            status: 'Open',
            description: 'No security contact file found at /.well-known/security.txt. RFC 9116 standardizes a machine-readable location for ethical security researchers to report vulnerabilities directly to your team.',
            evidence: `HTTP ${epResp.status} at /.well-known/security.txt`,
            impact: 'Security researchers and bug hunters may be unable to quickly and responsibly notify your organization of vulnerabilities.',
            remediation: {
              summary: 'Create a security.txt file adhering to RFC 9116 and host it at /.well-known/security.txt.',
              codeSnippet: `Contact: mailto:security@${hostname}\nExpires: 2027-01-01T00:00:00.000Z\nPreferred-Languages: en`
            }
          });
          emitLog('WARN', `Missing security.txt file (RFC 9116)`);
        }
      }
    } catch (e) {
      // Ignored for optional endpoints
    }
  }

  targetInfo.discoveredUrls = discoveredCount;

  // 6. Calculate Risk Score & Severity Breakdown
  const counts = {
    Critical: vulnerabilities.filter(v => v.severity === 'Critical').length,
    High: vulnerabilities.filter(v => v.severity === 'High').length,
    Medium: vulnerabilities.filter(v => v.severity === 'Medium').length,
    Low: vulnerabilities.filter(v => v.severity === 'Low').length,
    Total: vulnerabilities.length
  };

  // Weighted risk score calculation (0 to 10 scale)
  // Critical = 3.0, High = 1.8, Medium = 0.8, Low = 0.3
  let rawScore = (counts.Critical * 3.0) + (counts.High * 1.8) + (counts.Medium * 0.8) + (counts.Low * 0.3);
  if (counts.Critical > 0 && rawScore < 7.0) rawScore = 7.0 + (counts.Critical * 0.5);
  const calculatedRiskScore = Math.min(10.0, Math.max(0.0, Number(rawScore.toFixed(1))));

  const totalTimeSeconds = ((Date.now() - startTime) / 1000).toFixed(1);
  targetInfo.duration = `${totalTimeSeconds}s`;
  targetInfo.riskScore = calculatedRiskScore;
  targetInfo.status = 'Completed';

  // Extract external script dependencies from HTML
  const scriptRegex = /<script[^>]+src=["']([^"']+)["']/gi;
  const scripts = [];
  let sMatch;
  while ((sMatch = scriptRegex.exec(responseBodyText)) !== null) {
    scripts.push(sMatch[1]);
  }
  targetInfo.scripts = scripts.slice(0, 20);

  const pentestChecks = [
    { id: 'PT-01', name: 'Transport Layer Security (HTTPS Enforcement)', status: isHttps ? 'PASS' : 'FAIL', details: isHttps ? 'Site operates over encrypted HTTPS' : 'Insecure cleartext transmission' },
    { id: 'PT-02', name: 'Content Security Policy (CSP)', status: csp ? 'PASS' : 'FAIL', details: csp ? 'CSP header configured' : 'Missing CSP header' },
    { id: 'PT-03', name: 'Anti-Clickjacking Frame Sandboxing', status: (xfo || (csp && csp.includes('frame-ancestors'))) ? 'PASS' : 'FAIL', details: xfo || (csp && csp.includes('frame-ancestors') ? 'Protected via CSP frame-ancestors' : 'Missing X-Frame-Options') },
    { id: 'PT-04', name: 'MIME-Type Sniffing Defense', status: (xcto && xcto.includes('nosniff')) ? 'PASS' : 'FAIL', details: xcto || 'Missing nosniff attribute' },
    { id: 'PT-05', name: 'Referrer Information Leakage', status: refPol ? 'PASS' : 'WARN', details: refPol || 'Not explicitly declared' },
    { id: 'PT-06', name: 'Browser Hardware Permissions Policy', status: permPol ? 'PASS' : 'WARN', details: permPol || 'Missing Permissions-Policy' },
    { id: 'PT-07', name: 'Cross-Origin Resource Sharing (CORS)', status: (acao === '*' && acac === 'true') ? 'FAIL' : 'PASS', details: acao ? `Origin: ${acao}` : 'Restricted to same-origin' },
    { id: 'PT-08', name: 'RFC 9116 Responsible Disclosure (security.txt)', status: discoveredCount > 1 ? 'PASS' : 'WARN', details: 'Automated probe verified' },
    { id: 'PT-09', name: 'DMARC Domain Anti-Spoofing', status: hasDmarc ? 'PASS' : 'FAIL', details: hasDmarc ? 'DMARC record valid' : 'Missing DMARC policy' },
    { id: 'PT-10', name: 'Cryptographic Certificate Expiration', status: (targetInfo.tlsInfo?.daysRemaining > 15) ? 'PASS' : (targetInfo.tlsInfo ? 'WARN' : 'N/A'), details: targetInfo.tlsInfo ? `${targetInfo.tlsInfo.daysRemaining} days remaining` : 'Plaintext HTTP' }
  ];

  return {
    targetInfo,
    counts,
    securityHeaders,
    vulnerabilities,
    pentestChecks,
    rawHeaders: rawHeadersObj,
    logs
  };
}
