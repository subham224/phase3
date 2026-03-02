// src/components/HarvesterGobusterResults.js
import React from 'react';

/*
 * Renders subdomain enumeration results from Harvester and Gobuster.
 * @param {Object} props - Component props.
 * 
 * */


function HarvesterGobusterResults({ harvesterData, gobusterData }) {
  // Check for errors in the data
  const harvesterError = harvesterData && harvesterData.length > 0 && harvesterData[0].error;
  const gobusterError = gobusterData && gobusterData.length > 0 && gobusterData[0].error;

  if (harvesterError || gobusterError) {
    return (
      <div className="card no-results-message">
        <p>Subdomain enumeration failed:</p>
        {harvesterError && <p>Harvester Error: {harvesterError}</p>}
        {gobusterError && <p>Gobuster Error: {gobusterError}</p>}
      </div>
    );
  }

  if ((!harvesterData || harvesterData.length === 0) && (!gobusterData || gobusterData.length === 0)) {
    return (
      <div className="card no-results-message">
        <p>No results found for subdomain enumeration.</p>
      </div>
    );
  }

  return (
    <div >
      {harvesterData && harvesterData.length > 0 && (
        <React.Fragment>
          <h4>🌐 Discovered Subdomains & Hidden Directories</h4>
          <div className="table-responsive">
            <table>
              <tbody>
                {harvesterData.map((item, index) => (
                  <tr key={index}>
                    <td>{item.subdomain}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </React.Fragment>
      )}

      {gobusterData && gobusterData.length > 0 && (
        <React.Fragment>
          <div className="table-responsive">
            <table>
              <tbody>
                {gobusterData.map((item, index) => (
                  <tr key={index}>
                    <td>{item.subdomain}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </React.Fragment>
      )}
    </div>
  );
}

export default HarvesterGobusterResults;