// src/components/AiResponseAccordion.js
import React, { useState } from 'react';
import './App.css'; // Assuming App.css is used for general styles

const AiResponseAccordion = ({ title, vulnerabilities }) => {
  const [isOpen, setIsOpen] = useState(false);

  // Check if vulnerabilities exist and are an array
  if (!vulnerabilities || !Array.isArray(vulnerabilities) || vulnerabilities.length === 0) {
    return null;
  }

  const toggleAccordion = () => {
    setIsOpen(!isOpen);
  };

  return (
    <div className="ai-response-container">
      <div className="accordion-header" onClick={toggleAccordion}>
        <h3>AI Vulnerability Analysis</h3>
        <span className={`accordion-icon ${isOpen ? 'open' : ''}`}>&#9660;</span>
      </div>
      {isOpen && (
        <div className="accordion-body">
          {vulnerabilities.map((vuln, index) => (
            <div key={index} className="vulnerability-item">
              {/*<h4>{vuln.Vulnerability}</h4>*/}
              <p><strong>⚠️ Vulnerability:</strong>{vuln.Vulnerability}</p>
              <p><strong>🖋️ Description:</strong> {vuln.Description}</p>
              <p><strong>⚡ Impact:</strong> {vuln.Impact}</p>
              <p><strong>🛠️ Remediation:</strong> {vuln.Remediation}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default AiResponseAccordion;