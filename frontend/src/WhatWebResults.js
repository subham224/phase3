// src/components/WhatWebResults.js
import React from 'react';

/**
 * Renders the results from a WhatWeb scan.
 * @param {Object} props - Component props.
 * @param {Array} props.data - Array of WhatWeb scan results.
 */
function WhatWebResults({ data }) {
  if (!data || data.length === 0) {
    return (
      <div className="card no-results-message">
        <p>No WhatWeb results found for the target.</p>
      </div>
    );
  }

  return (
    <div>
      
      <p>🔍 Identified technologies and server information for the target URL.</p>
      {/*<h4>Details:</h4>*/}
      <div className="table-responsive">
        <table>
          <thead>
            <tr>
              <th>HTTP Server</th>
              <th>IP</th>
            </tr>
          </thead>
          <tbody>
            {data.map((item, index) => (
              <tr key={index}>
                <td>{item.HTTPServer || 'N/A'}</td>
                <td>{item.IP || 'N/A'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default WhatWebResults;