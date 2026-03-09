import React, { useState, useEffect } from 'react';
import './App.css';
import ScanResults from './ScanResults';
import { v4 as uuidv4 } from 'uuid';
import AnimatedTechBackground from './AnimatedTechBackground';

// Helper for dynamic backend URL
const getBackendUrl = () => {
  // If the environment variable exists (Production/Configured), use it.
  // Otherwise, fall back to the dynamic localhost logic (Local Development).
  return process.env.REACT_APP_API_URL || `http://${window.location.hostname}:8000`;
};

const getWsUrl = () => {
  // We need to convert http/https to ws/wss for WebSockets
  const backendUrl = getBackendUrl();
  const wsProtocol = backendUrl.startsWith('https') ? 'wss' : 'ws';
  // Remove the 'http://' or 'https://' to append the correct WS protocol
  const cleanUrl = backendUrl.replace(/^https?:\/\//, '');
  return `${wsProtocol}://${cleanUrl}/ws/scan_progress`;
};

export default function App() {
  const [targetUrl, setTargetUrl] = useState('');
  const [scanType, setScanType] = useState('deep');
  const [scanLoading, setScanLoading] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [scanError, setScanError] = useState(null);
  const [scanSummaryForAI, setScanSummaryForAI] = useState([]);
  const [aiResponse, setAiResponse] = useState('');
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState('');
  const [scanProgress, setScanProgress] = useState(0);
  const [progressStep, setProgressStep] = useState('Initializing');
  const [websocket, setWebsocket] = useState(null);

  const connectWebSocket = (scanId) => {
    const ws = new WebSocket(getWsUrl());
    let retryCount = 0;
    const maxRetries = 3;

    ws.onopen = () => {
      console.log('WebSocket connected');
      setTimeout(() => {
        ws.send(JSON.stringify({ scan_id: scanId }));
      }, 500);
      setWebsocket(ws);
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.scan_id === scanId) {
          setScanProgress(data.progress || 0);
          setProgressStep(data.step || 'Initializing');
          if (data.status === 'failed') {
            setScanError(data.error || 'Scan failed');
            setScanLoading(false);
            ws.close();
          } else if (data.status === 'completed') {
            ws.close();
          }
        }
      } catch (err) {}
    };

    ws.onclose = () => setWebsocket(null);
    return ws;
  };

  const handleScanSubmit = async () => {
    setScanLoading(true);
    setScanError(null);
    setScanResult(null);
    setScanSummaryForAI([]);
    setScanProgress(0);
    setProgressStep('Initializing');

    const scanId = uuidv4();
    const ws = connectWebSocket(scanId);

    try {
      const response = await fetch(`${getBackendUrl()}/api/v1/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target: targetUrl,
          scan_type: scanType === 'deep' ? 'deep_scan' : 'light_scan',
          scan_id: scanId
        }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || `HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      setScanResult(data);

      let summaryList = [];
      if (data.whatweb_info) summaryList.push({ results: data.whatweb_info });
      setScanSummaryForAI(summaryList);

      // FIX: Stop loading so results appear!
      setScanLoading(false);

    } catch (err) {
      console.error('Scan Error:', err);
      setScanError(err.message || 'Failed to connect to backend.');
      setScanLoading(false);
      if (ws) ws.close();
    }
  };

  useEffect(() => {
    return () => { if (websocket) websocket.close(); };
  }, [websocket]);

  return (
    <div className="App">
      <AnimatedTechBackground />
      <div style={{ position: 'relative', zIndex: 10, width: '100%', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
        <header className="App-header">
          <h1>Automated Pentesting Tool</h1>
        </header>

        <main>
          <section className="scan-form">
            <h2>Perform a Scan</h2>
            <label htmlFor="targetUrl">Target URL:</label>
            <input
              type="text"
              id="targetUrl"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="http://example.com"
              required
              disabled={scanLoading}
            />

            {scanLoading && (
              <div className="progress-bar-container">
                <div className="progress-bar" style={{ width: `${scanProgress}%` }}></div>
              </div>
            )}
            {/* {scanLoading && <div className="progress-text">{Math.round(scanProgress)}% - {progressStep}</div>} */}
            {scanLoading && <div className="progress-text">{Math.round(scanProgress)}%</div>}


            <div className="radio-group">
              <label>
                <input type="radio" name="scanType" value="light" checked={scanType === 'light'} onChange={() => setScanType('light')} disabled={scanLoading} />
                <span>Light Scan</span>
              </label>
              <label>
                <input type="radio" name="scanType" value="deep" checked={scanType === 'deep'} onChange={() => setScanType('deep')} disabled={scanLoading} />
                <span>Deep Scan</span>
              </label>
            </div>

            <button onClick={handleScanSubmit} disabled={scanLoading || !targetUrl.trim()}>
              {scanLoading ? 'Scanning...' : 'Start'}
            </button>
          </section>

          {scanError && <div className="error-message">{scanError}</div>}
          
          {/* ScanResults will now render properly */}
          {scanResult && <ScanResults results={scanResult} />}
        </main>
        
        <footer className="App-footer">
          <p>© {new Date().getFullYear()} Automated Pentool App. All rights reserved</p>
        </footer>
      </div>
    </div>
  );
}