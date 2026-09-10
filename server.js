import express from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import { runCyberProbeScan } from './scanner.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Store recent scans in-memory
const scanHistory = [];

/**
 * Health check / Status
 */
app.get('/api/status', (req, res) => {
  res.json({
    name: 'CyberProbe Engine',
    version: '1.0.0',
    status: 'Standby',
    standards: ['OWASP 2024', 'CWE', 'NIST SP 800-115'],
    activeScans: 0
  });
});

/**
 * Standard POST Scan endpoint (returns complete report once completed)
 */
app.post('/api/scan', async (req, res) => {
  const { targetUrl, scanProfile } = req.body;
  if (!targetUrl) {
    return res.status(400).json({ error: 'Target URL is required.' });
  }

  try {
    const result = await runCyberProbeScan(targetUrl, scanProfile || 'Full Pen-Test');
    scanHistory.unshift({
      id: Date.now().toString(),
      targetUrl: result.targetInfo.targetUrl,
      riskScore: result.targetInfo.riskScore,
      counts: result.counts,
      timestamp: new Date().toISOString(),
      result
    });

    if (scanHistory.length > 20) {
      scanHistory.pop();
    }

    res.json({ success: true, ...result });
  } catch (err) {
    console.error('Scan Error:', err);
    res.status(500).json({ error: err.message || 'Failed to scan target' });
  }
});

/**
 * Server-Sent Events (SSE) endpoint for real-time live terminal streaming scan
 */
app.get('/api/scan-stream', async (req, res) => {
  const targetUrl = req.query.url;
  const scanProfile = req.query.profile || 'Full Pen-Test';

  if (!targetUrl) {
    return res.status(400).send('Target URL parameter is required.');
  }

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders?.();

  const sendEvent = (event, data) => {
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  };

  try {
    sendEvent('status', { state: 'initializing', message: `Initializing engine for ${targetUrl}...` });

    const result = await runCyberProbeScan(targetUrl, scanProfile, (logEntry) => {
      sendEvent('log', logEntry);
    });

    scanHistory.unshift({
      id: Date.now().toString(),
      targetUrl: result.targetInfo.targetUrl,
      riskScore: result.targetInfo.riskScore,
      counts: result.counts,
      timestamp: new Date().toISOString(),
      result
    });

    sendEvent('complete', result);
  } catch (err) {
    sendEvent('error', { message: err.message || 'Scan execution error' });
  } finally {
    res.end();
  }
});

/**
 * Recent scan history
 */
app.get('/api/history', (req, res) => {
  res.json(scanHistory.map(h => ({
    id: h.id,
    targetUrl: h.targetUrl,
    riskScore: h.riskScore,
    counts: h.counts,
    timestamp: h.timestamp
  })));
});

app.listen(PORT, () => {
  console.log(`
====================================================

 ██████╗ ██╗  ██╗███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ███╗   ██╗
██╔═████╗╚██╗██╔╝██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗████╗  ██║
██║██╔██║ ╚███╔╝ ███████╗███████║███████║██████╔╝██║   ██║██╔██╗ ██║
████╔╝██║ ██╔██╗ ╚════██║██╔══██║██╔══██║██╔══██╗██║   ██║██║╚██╗██║
╚██████╔╝██╔╝ ██╗███████║██║  ██║██║  ██║██║  ██║╚██████╔╝██║ ╚████║
 ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

                     0x S H A R O N
                 // SECURITY RESEARCHER //

====================================================
🛡️  CYBERPROBE - Security Engine Online
📡 Server running at http://localhost:${PORT}
🎯 Real Web Vulnerability & Penetration Suite Ready
⚡ 0xSHARON // INITIALIZING SECURITY PROTOCOLS...
====================================================
`);
});