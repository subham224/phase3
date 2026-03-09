// src/components/NmapResults.js
import React, { useState } from 'react';
import { Bar } from 'react-chartjs-2';
import { Chart as ChartJS, CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend } from 'chart.js';
import NmapHostAccordionItem from './NmapHostAccordionItem';

// Register Chart.js components
ChartJS.register(CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend);

/**
 * Renders the results of all Nmap scans (e.g., light, deep).
 * @param {Object} props - Component props.
 * @param {Object} props.data - An object where keys are scan types and values are scan results.
 */
function NmapResults({ data }) {
  const [activeTab, setActiveTab] = useState('summary');

  if (!data || Object.keys(data).length === 0) {
    return (
      <div className="card no-results-message">
        <p>No Nmap scan results found for the target.</p>
      </div>
    );
  }

  // Flatten all Nmap results into a single array of ports for the detailed view
  const getAllPorts = () => {
    const allPorts = [];
    for (const scanType in data) {
      if (data[scanType] && data[scanType].hosts) {
        data[scanType].hosts.forEach(host => {
          host.ports.forEach(port => {
            allPorts.push({ ...port, host: host.address, scanType: scanType, hostname: host.hostname });
          });
        });
      }
    }
    return allPorts;
  };

  const allPorts = getAllPorts();

  
  // Collect all unique ciphers from all ports for the 'Ciphers' tab
  const getUniqueCiphers = () => {
    const uniqueCiphersMap = new Map();
    allPorts.forEach(port => {
      if (port.cipher_details && port.cipher_details.length > 0) {
        port.cipher_details.forEach(cipher => {
          // Create a unique key based on all cipher properties
          const key = `${cipher.name}-${cipher.kex}-${cipher.auth}-${cipher.bits}-${cipher.strength}`;
          if (!uniqueCiphersMap.has(key)) {
            uniqueCiphersMap.set(key, cipher);
          }
        });
      }
    });
    return Array.from(uniqueCiphersMap.values());
  };
  
  const uniqueCiphers = getUniqueCiphers();


  return (
    <div >
      
      <p style={{margin:10}}>📊 Detailed network and host information, including open ports, services.</p>

      <div className="tabs">
             <button onClick={() => setActiveTab('details')} className={activeTab === 'details' ? 'active' : ''}>Ports Details</button>
        <button onClick={() => setActiveTab('ciphers')} className={activeTab === 'ciphers' ? 'active' : ''}>Ciphers Details</button>
      </div>


      {activeTab === 'details' && (
        <div className="details-section">
          <h4>🔌 All Discovered Ports:</h4>
          <div className="table-responsive">
            <table>
              <thead>
                <tr>
                  <th>Host</th>
                  <th>Hostname</th>
                  <th>Port</th>
                  <th>Protocol</th>
                  <th>State</th>
                  <th>Service</th>
                  <th>Reason</th>
                 
                </tr>
              </thead>
              <tbody>
                {allPorts.map((port, index) => (
                  <tr key={index}>
                    <td>{port.host}</td>
                    <td>{port.hostname || 'N/A'}</td>
                    <td>{port.portid}</td>
                    <td>{port.protocol}</td>
                    <td>{port.state}</td>
                    <td>{port.service || 'N/A'}</td>
                    {/* <td>{port.reason || "-"}</td> */}
                    <td>{port.reason === 'no-response' ? '--' : (port.reason || '-')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {activeTab === 'ciphers' && (
        uniqueCiphers.length > 0 ? (
          <div className="cipher-details">
            <p>🔐The following unique SSL/TLS ciphers were found on scanned hosts:</p>
            <div className="table-responsive">
              <table>
                <thead>
                  <tr>
                    <th>Cipher</th>
                    <th>Strength</th>
                  </tr>
                </thead>
                <tbody>
                  {uniqueCiphers.map((cipher, index) => (
                    <tr key={index}>
                       {/* New, more complete rendering for the cipher name column */}
                       <td>{`${cipher.name || 'N/A'}`}{cipher.raw_kex_auth ? ` (${cipher.raw_kex_auth})` : ''}</td>
                    
                      {/* <td>{`${cipher.name || 'N/A'} (${cipher.kex || 'N/A'})`}</td>*/}
                       <td>{cipher.strength || 'N/A'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ) : (
          <p>No SSL/TLS cipher details were found during the scan.</p>
        )
      )}
    </div>
  );
}

export default NmapResults;