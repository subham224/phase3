import React, { useState, useEffect } from 'react';
import WhatWebResults from './WhatWebResults';
import HarvesterGobusterResults from './HarvesterGobusterResults';
import NmapResults from './NmapResults';
import WapitiResults from './WapitiResults';
import SkipfishResults from './SkipfishResults';
import AiResponseAccordion from './AiResponseAccordion';
import SqlmapResults from './SqlmapResults';
import MetasploitResults from "./MetasploitResults";

const getBackendUrl = () => {
  if (process.env.REACT_APP_API_URL) {
    return process.env.REACT_APP_API_URL;
  }
  const hostname = window.location.hostname;
  return `http://${hostname}:8000`;
};

function ScanResults({ results }) {
  const [aiData, setAiData] = useState({});
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState(null);

  // Fetch the SINGLE Executive Summary AI File
  useEffect(() => {
    if (!results || !results.ai_output_files || !results.ai_output_files.executive_summary) {
      return;
    }

    const fetchAiData = async () => {
      setAiLoading(true);
      setAiError(null);

      try {
        const execSummaryFile = results.ai_output_files.executive_summary[0];
        
        // Ensure path starts with scans/ depending on how backend sent it
        const relativePath = execSummaryFile.startsWith('scans/') 
          ? execSummaryFile 
          : `scans/${execSummaryFile}`;

        const url = `${getBackendUrl()}/${relativePath}`;
        
        const response = await fetch(url);
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const data = await response.json();
        setAiData(data);

      } catch (err) {
        console.error("Critical error fetching Executive AI summary:", err);
        setAiError("Failed to load AI Executive Summary.");
      } finally {
        setAiLoading(false);
      }
    };

    fetchAiData();
  }, [results]);

  if (!results) {
    return <div className="card no-results-message"><p>No scan results available.</p></div>;
  }

  // Extract threats or API quota errors from the fetched data
  const threats = aiData?.threats;
  const backendAiError = aiData?.error;

  return (
    <div className="scan-results-container">
      {/* <h2 style={{ fontSize: '1.8rem', fontWeight: 'bold', marginBottom: '20px', color: '#60a5fa' }}>
        Pentest Report: {results.target}
      </h2> */}

      {/* ============================================== */}
      {/* 🌟 AI EXECUTIVE SUMMARY (TOP LEVEL) 🌟 */}
      {/* ============================================== */}
      {aiLoading && <p style={{textAlign:'center', color:'#9ca3af', marginBottom: '20px'}}>Analyzing Combined Pentest Data with AI...</p>}
      {aiError && <p style={{textAlign:'center', color:'#ef4444', marginBottom: '20px'}}>{aiError}</p>}

      {/* Handle Gemini Quota Limit Error Display */}
      {backendAiError && (
        <div className="card error-message" style={{ color: '#fbbf24', padding: '15px', marginBottom: '20px', border: '1px solid #b45309', backgroundColor: '#451a03', borderRadius: '8px' }}>
          <strong>AI Analysis Skipped: </strong> {backendAiError}
        </div>
      )}

     

      {/* 1. WhatWeb */}
      {results.whatweb_info && results.whatweb_info.length > 0 && (
        <div className="card">
          <WhatWebResults data={results.whatweb_info} />
        </div>
      )}

      {/* 2. Recon (Harvester/Gobuster) */}
      {(results.harvester_info?.length > 0 || results.gobuster_info?.length > 0) && (
        <div className="card">
          <HarvesterGobusterResults
            harvesterData={results.harvester_info}
            gobusterData={results.gobuster_info}
          />
        </div>
      )}

      {/* 3. Nmap */}
      {results.nmap_info && Object.keys(results.nmap_info).length > 0 && (
        <div className="card">
          <NmapResults data={results.nmap_info} />
        </div>
      )}

      {/* 4. Wapiti & Skipfish */}
      <div className="card">
        {results.wapiti_info && <WapitiResults data={results.wapiti_info} />}
        {results.skipfish_info && <SkipfishResults data={results.skipfish_info} />}
      </div>

      {/* 5. SQLMap */}
      {results.sqlmap_info && (
        <div className="card">
          <SqlmapResults data={results.sqlmap_info} />
        </div>
      )}

      {/* Render AI Threats Accordion */}
      {threats && threats.length > 0 && (
        <div className="card" style={{ marginBottom: '30px', border: '1px solid #4f46e5', backgroundColor: '#1e1b4b' }}>
          {/* <h3 style={{ color: '#818cf8', fontSize: '1.4rem', fontWeight: 'bold', marginBottom: '15px' }}>
            AI Executive Summary
          </h3> */}
          <AiResponseAccordion 
            title="Combined Threat Analysis" 
            vulnerabilities={threats} 
          />
        </div>
      )}

      {/* 6. Metasploit Vulnerabilities */}
      {results.metasploit_info && (
        <div className="card">
          <MetasploitResults metasploitResults={results.metasploit_info} />
        </div>
      )}

    </div>
  );
}

export default ScanResults;