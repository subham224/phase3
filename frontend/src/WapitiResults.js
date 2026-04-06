// src/components/WapitiResults.js
import React from 'react';
import { Pie } from 'react-chartjs-2';
import { Chart as ChartJS, ArcElement, Tooltip, Legend, Title } from 'chart.js';

// Register Chart.js components
ChartJS.register(ArcElement, Tooltip, Legend, Title);

/**
 * Renders the results of a Wapiti scan.
 * @param {Object} props - Component props.
 * @param {Object} props.data - The raw Wapiti results object.
 */
function WapitiResults({ data }) {
  if (!data || !data.vulnerabilities || data.vulnerabilities.length === 0) {
    return (
      <div className="card no-results-message">
        <p>No Wapiti vulnerabilities found for the target.</p>
      </div>
    );
  }

  // Deduplicate vulnerabilities by 'info' field for display
  const uniqueVulnerabilitiesMap = data.vulnerabilities.reduce((acc, vul) => {
    const info = vul.info || 'N/A';
    if (!acc[info]) {
      acc[info] = { info: info, count: 0 };
    }
    acc[info].count++;
    return acc;
  }, {});
  const dedupedVulnerabilities = Object.values(uniqueVulnerabilitiesMap);

  
  return (
    <div >
      <h4>⚠️ Discovered Vulnerabilities:</h4>
      <div className="table-responsive">
        <table>
          <thead>
            <tr>
              <th>Vulnerability Info</th>
            </tr>
          </thead>
          <tbody>
            {dedupedVulnerabilities.map((vul, index) => (
              <tr key={index}>
                <td>{vul.info}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default WapitiResults;