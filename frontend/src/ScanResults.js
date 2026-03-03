import React, { useState, useEffect } from 'react';
import WhatWebResults from './WhatWebResults';
import HarvesterGobusterResults from './HarvesterGobusterResults';
import NmapResults from './NmapResults';
import WapitiResults from './WapitiResults';
import SkipfishResults from './SkipfishResults';
import AiResponseAccordion from './AiResponseAccordion';
import SqlmapResults from './SqlmapResults';

// FIX: Use the same logic as App.js to ensure it works in Production (Render) and Local
const getBackendUrl = () => {
  // 1. If the Env Var is set (Best practice for Render), use it.
  if (process.env.REACT_APP_API_URL) {
    return process.env.REACT_APP_API_URL;
  }
  
  // 2. If running locally (hostname is localhost or IP), assume port 8000.
  //    But if running in prod without env var, this might still break if port is 80/443.
  const hostname = window.location.hostname;
  return `http://${hostname}:8000`;
};

function ScanResults({ results }) {
  const [aiData, setAiData] = useState({});
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState(null);

  useEffect(() => {
    if (!results || !results.ai_output_files) {
      return;
    }

    const fetchAiData = async () => {
      setAiLoading(true);
      setAiError(null);
      const fetchedData = {};
      const filePaths = results.ai_output_files;

      try {
        const promises = [];
        const tools = [];

        for (const tool in filePaths) {
          if (filePaths[tool] && filePaths[tool].length > 0) {
            // Backend sends "scans/filename.json" (Relative Path)
            const relativePath = filePaths[tool][0];
            const url = `${getBackendUrl()}/${relativePath}`;
            
            const fetchPromise = fetch(url)
              .then(async (response) => {
                if (!response.ok) {
                  console.warn(`[ScanResults] Failed to fetch AI data for ${tool}: ${response.status}`);
                  return null;
                }
                return response.json();
              })
              .catch((err) => {
                console.warn(`[ScanResults] Network error fetching ${tool}:`, err);
                return null;
              });

            promises.push(fetchPromise);
            tools.push(tool);
          }
        }

        const responses = await Promise.all(promises);

        responses.forEach((data, index) => {
          if (data) {
            fetchedData[tools[index]] = data;
          }
        });

        setAiData(fetchedData);
      } catch (err) {
        console.error("Critical error in AI fetch logic:", err);
        setAiError("Failed to initialize AI data loaders.");
      } finally {
        setAiLoading(false);
      }
      
    };

    fetchAiData();
  }, [results]);

  const getAiResponse = (toolName) => {
    // If backend returned { "error": "..." } instead of threats, log it or handle it.
    // Currently, we just return safe access to threats.
    return aiData[toolName]?.threats;
  };


  // NEW: Helper to get the error message from the backend JSON
  const getAiBackendError = (toolName) => {
    return aiData[toolName]?.error;
  };

  if (!results) {
    return <div className="card no-results-message"><p>No scan results available.</p></div>;
  }

  return (
    <>
      {/* 1. WhatWeb */}
      <div className="card">
        <WhatWebResults data={results.whatweb_info} />
        {getAiResponse('whatweb') && (
            <AiResponseAccordion title="WhatWeb AI Analysis" vulnerabilities={getAiResponse('whatweb')} />
        )}
      </div>

      {/* 2. Recon (Harvester/Gobuster) */}
      <div className="card">
        <HarvesterGobusterResults
          harvesterData={results.harvester_info}
          gobusterData={results.gobuster_info}
        />
        {/* Check for either harvester OR gobuster AI output */}
        {getAiResponse('harvester') && (
            <AiResponseAccordion title="Harvester AI Analysis" vulnerabilities={getAiResponse('harvester')} />
        )}
        {getAiResponse('gobuster') && (
            <AiResponseAccordion title="Gobuster AI Analysis" vulnerabilities={getAiResponse('gobuster')} />
        )}
      </div>

      {/* 3. Nmap */}
      <div className="card">
         <NmapResults data={results.nmap_info} />
        {/* {getAiResponse('nmap') && (
            <AiResponseAccordion title="Nmap AI Analysis" vulnerabilities={getAiResponse('nmap')} />
        )} */}

        {/* Display Error if Backend sent one */}
        {getAiBackendError('nmap') && (
            <div className="error-message" style={{color: 'red', padding: '10px'}}>
                <strong>AI Error:</strong> {getAiBackendError('nmap')}
            </div>
        )}

        {/* Display Accordion only if threats exist */}
        {getAiResponse('nmap') && (
            <AiResponseAccordion title="Nmap AI Analysis" vulnerabilities={getAiResponse('nmap')} />
        )}
      </div>

      {/* 4. Wapiti & Skipfish */}
      <div className="card">
        <WapitiResults data={results.wapiti_info} />
        {getAiResponse('wapiti') && (
            <AiResponseAccordion title="Wapiti AI Analysis" vulnerabilities={getAiResponse('wapiti')} />
        )}

        <SkipfishResults data={results.skipfish_info} />
        {getAiResponse('skipfish') && (
            <AiResponseAccordion title="Skipfish AI Analysis" vulnerabilities={getAiResponse('skipfish')} />
        )}
      </div>
      
      {aiLoading && <p style={{textAlign:'center', color:'#666'}}>Loading AI analysis...</p>}
      {aiError && <p style={{textAlign:'center', color:'red'}}>{aiError}</p>}

      {/* SQLMap Results */}
      {results.sqlmap_info && (
        <div className="mb-6">
          <SqlmapResults data={results.sqlmap_info} />
          <AiResponseAccordion 
            aiFiles={results.ai_output_files?.sqlmap} 
            toolName="SQLMap" 
          />
        </div>
      )}
    </>
  );
}

export default ScanResults;