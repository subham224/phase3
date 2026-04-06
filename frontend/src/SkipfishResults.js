// src/components/SkipfishResults.js
import React, { useState, useEffect } from 'react';
import { Pie, Doughnut } from 'react-chartjs-2';
import { Chart as ChartJS, ArcElement, Tooltip, Legend, Title } from 'chart.js';

// Register Chart.js components
ChartJS.register(ArcElement, Tooltip, Legend, Title);

/**
 * Renders the results of a Skipfish scan.
 * @param {Object} props - Component props.
 * @param {Object} props.data - The raw Skipfish results object.
 * 
 */



const getBackendUrl = () => {
  if (process.env.REACT_APP_API_URL) {
    return process.env.REACT_APP_API_URL;
  }
  return `http://${window.location.hostname}:8000`;
};

function SkipfishResults({ data }) {
  const [issueDescriptions, setIssueDescriptions] = useState({});
  const [loadingDescriptions, setLoadingDescriptions] = useState(true);
  const [errorDescriptions, setErrorDescriptions] = useState(null);

  // Fetch issue descriptions from the backend on component mount
  useEffect(() => {

    fetch(`${getBackendUrl()}/api/v1/issues`) // <--- Use dynamic URL
    .then(res => res.json())


    const fetchIssueDescriptions = async () => {
      try {
        const response = await fetch(`${getBackendUrl()}/api/v1/issues`);
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        const result = await response.json();
        setIssueDescriptions(result || {});
      } catch (error) {
        console.error("Error fetching Skipfish issue descriptions:", error);
        setErrorDescriptions(error.message);
      } finally {
        setLoadingDescriptions(false);
      }
    };

    fetchIssueDescriptions();
  }, []);

  if (!data || !data.issue_samples || data.issue_samples.length === 0) {
    return (
      <div className="card no-results-message">
        <p>No Skipfish issue samples found for the target.</p>
      </div>
    );
  }

  const { issue_samples } = data;

  // Use fetched descriptions, with a fallback for robustness
  const fallbackDescriptions = {
    // A comprehensive list of hardcoded descriptions as a fallback
    "10101": "SSL certificate issuer information", "10201": "New HTTP cookie added", "10202": "New 'Server' header value seen", "10203": "New 'Via' header value seen", "10204": "New 'X-*' header value seen", "10205": "New 404 signature seen", "10401": "Resource not directly accessible", "10402": "HTTP authentication required", "10403": "Server error triggered", "10404": "Directory listing enabled", "10405": "Hidden files / directories", "10501": "All external links", "10502": "External URL redirector", "10503": "All e-mail addresses", "10504": "Links to unknown protocols", "10505": "Unknown form field (can't autocomplete)", "10601": "HTML form (not classified otherwise)", "10602": "Password entry form - consider brute-force", "10603": "File upload form", "10701": "User-supplied link rendered on a page", "10801": "Incorrect or missing MIME type (low risk)", "10802": "Generic MIME used (low risk)", "10803": "Incorrect or missing charset (low risk)", "10804": "Conflicting MIME / charset info (low risk)", "10901": "Numerical filename - consider enumerating", "10902": "OGNL-like parameter behavior", "10909": "Signature match (informational)", "20101": "Resource fetch failed", "20102": "Limits exceeded, fetch suppressed", "20201": "Directory behavior checks failed (no brute force)", "20202": "Parent behavior checks failed (no brute force)", "20203": "IPS filtering enabled", "20204": "IPS filtering disabled again", "20205": "Response varies randomly, skipping checks", "20301": "Node should be a directory, detection error?", "30101": "HTTP credentials seen in URLs", "30201": "SSL certificate expired or not yet valid", "30202": "Self-signed SSL certificate", "30203": "SSL certificate host name mismatch", "30204": "No SSL certificate data found", "30205": "Weak SSL cipher negotiated", "30206": "Host name length mismatch (name string has null byte)", "30301": "Directory listing restrictions bypassed", "30401": "Redirection to attacker-supplied URLs", "30402": "Attacker-supplied URLs in embedded content (lower risk)", "30501": "External content embedded on a page (lower risk)", "30502": "Mixed content embedded on a page (lower risk)", "30503": "HTTPS form submitting to a HTTP URL", "30601": "HTML form with no apparent XSRF protection", "30602": "JSON response with no apparent XSSI protection", "30603": "Auth form leaks credentials via HTTP GET", "30701": "Incorrect caching directives (lower risk)", "30801": "User-controlled response prefix (BOM / plugin attacks)", "30901": "HTTP header injection vector", "30909": "Signature match detected", "40101": "XSS vector in document body", "40102": "XSS vector via arbitrary URLs", "40103": "HTTP response header splitting", "40104": "Attacker-supplied URLs in embedded content (higher risk)", "40105": "XSS vector via injected HTML tag attribute", "40201": "External content embedded on a page (higher risk)", "40202": "Mixed content embedded on a page (higher risk)", "40301": "Incorrect or missing MIME type (higher risk)", "40302": "Generic MIME type (higher risk)", "40304": "Incorrect or missing charset (higher risk)", "40305": "Conflicting MIME / charset info (higher risk)", "40401": "Interesting file", "40402": "Interesting server message", "40501": "Directory traversal / file inclusion possible", "40601": "Incorrect caching directives (higher risk)", "40701": "Password form submits from or to non-HTTPS page", "40909": "Signature match detected (high risk)", "50101": "Server-side XML injection vector", "50102": "Shell injection vector", "50103": "Query injection vector", "50104": "Format string vector", "50105": "Integer overflow vector", "50106": "File inclusion", "50107": "Remote file inclusion", "50201": "SQL query or similar syntax in parameters", "50301": "PUT request accepted", "50909": "Signature match detected (high risk)"
  };
  const finalDescriptions = { ...fallbackDescriptions, ...issueDescriptions };

  // Aggregate severity and type counts for charts
  const severityCounts = issue_samples.reduce((acc, sample) => {
    const severity = sample.severity || 'Unknown';
    acc[severity] = (acc[severity] || 0) + 1;
    return acc;
  }, {});

  const typeCounts = issue_samples.reduce((acc, sample) => {
    const type = sample.type || 'Unknown';
    acc[type] = (acc[type] || 0) + 1;
    return acc;
  }, {});

  const getSeverityClass = (severity) => {
    switch (String(severity).toLowerCase()) {
      case 'high': return 'severity-high';
      case 'medium': return 'severity-medium';
      case 'low': return 'severity-low';
      case 'info': return 'severity-info';
      case 'critical': return 'severity-critical';
      default: return '';
    }
  };


  return (
    <div >
        
      <div >
        <p>🔓Detailed report of potential vulnerabilities discovered </p>
      
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              {/* <th>Type</th> */}
              <th>Description</th>
              <th>URL</th>
            </tr>
          </thead>
          <tbody>
            {issue_samples.map((sample, index) => (
              <tr key={index} className={getSeverityClass(sample.severity)}>
                <td>{sample.severity || 'N/A'}</td>
                {/* <td>{sample.type || 'N/A'}</td> */}
                <td>{finalDescriptions[String(sample.type)] || 'No detailed description available.'}</td>
                <td><a href={sample.url} target="_blank" rel="noopener noreferrer">{sample.url || 'N/A'}</a></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default SkipfishResults;