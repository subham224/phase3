import React, { useState } from 'react';

/*
 * Renders enumeration results from Sublist3r (Subdomains) and Gobuster (Directories).
 * @param {Object} props - Component props.
 */

function HarvesterGobusterResults({ sublist3rData, gobusterData }) {
  // State to track if the user wants to see all items
  const [showAllSubdomains, setShowAllSubdomains] = useState(false);
  const [showAllDirectories, setShowAllDirectories] = useState(false);
  
  // How many items to show initially
  const INITIAL_LIMIT = 10;

  // Check for errors in the data
  const sublist3rError = sublist3rData && sublist3rData.length > 0 && sublist3rData[0].error;
  const gobusterError = gobusterData && gobusterData.length > 0 && gobusterData[0].error;

  if (sublist3rError || gobusterError) {
    return (
      <div className="card no-results-message">
        <p>Enumeration failed:</p>
        {sublist3rError && <p>Sublist3r Error: {sublist3rError}</p>}
        {gobusterError && <p>Gobuster Error: {gobusterError}</p>}
      </div>
    );
  }

  if ((!sublist3rData || sublist3rData.length === 0) && (!gobusterData || gobusterData.length === 0)) {
    return (
      <div className="card no-results-message">
        <p>No results found for enumeration.</p>
      </div>
    );
  }

  // Calculate the items to display based on the state toggle
  const displayedSubdomains = sublist3rData ? (showAllSubdomains ? sublist3rData : sublist3rData.slice(0, INITIAL_LIMIT)) : [];
  const hasMoreSubdomains = sublist3rData && sublist3rData.length > INITIAL_LIMIT;

  const displayedDirectories = gobusterData ? (showAllDirectories ? gobusterData : gobusterData.slice(0, INITIAL_LIMIT)) : [];
  const hasMoreDirectories = gobusterData && gobusterData.length > INITIAL_LIMIT;

  // Reusable button style to match your dark/tech theme
  const toggleButtonStyle = {
    marginTop: '10px',
    background: 'none',
    border: 'none',
    color: '#3b38f8', // Tailwind sky-400 color
    cursor: 'pointer',
    fontWeight: 'bold',
    fontSize: '0.9rem',
    padding: '5px 0'
  };

  return (
    <div>
      {/* ========================================= */}
      {/* Sublist3r Section (Subdomains)            */}
      {/* ========================================= */}
      {sublist3rData && sublist3rData.length > 0 && (
        <React.Fragment>
          <h4>🌐 Discovered Subdomains</h4>
          <div className="table-responsive">
            <table>
              <thead>
                <tr>
                  <th style={{ textAlign: 'left', paddingBottom: '10px' }}>Subdomain</th>
                </tr>
              </thead>
              <tbody>
                {displayedSubdomains.map((item, index) => (
                  <tr key={`sub-${index}`}>
                    <td>{item.subdomain}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          
          {/* "See More" Toggle for Subdomains */}
          {hasMoreSubdomains && (
            <button 
              onClick={() => setShowAllSubdomains(!showAllSubdomains)} 
              style={toggleButtonStyle}
            >
              {showAllSubdomains 
                ? '▲ See Less' 
                : `▼ See More (${sublist3rData.length - INITIAL_LIMIT} more)`}
            </button>
          )}
        </React.Fragment>
      )}

      {/* ========================================= */}
      {/* Gobuster Section (Directories)            */}
      {/* ========================================= */}
      {gobusterData && gobusterData.length > 0 && (
        <React.Fragment>
          <h4 style={{ marginTop: '20px' }}>📂 Discovered Directories & Files</h4>
          <div className="table-responsive">
            <table>
              <thead>
                <tr>
                  <th style={{ textAlign: 'left', paddingBottom: '10px' }}>Path</th>
                </tr>
              </thead>
              <tbody>
                {displayedDirectories.map((item, index) => (
                  <tr key={`dir-${index}`}>
                    <td>{item.subdomain}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* "See More" Toggle for Directories */}
          {hasMoreDirectories && (
            <button 
              onClick={() => setShowAllDirectories(!showAllDirectories)} 
              style={toggleButtonStyle}
            >
              {showAllDirectories 
                ? '▲ See Less' 
                : `▼ See More (${gobusterData.length - INITIAL_LIMIT} more)`}
            </button>
          )}
        </React.Fragment>
      )}
    </div>
  );
}

export default HarvesterGobusterResults;