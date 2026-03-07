import React, { useState } from "react";

export default function MetasploitResults({ metasploitResults }) {
  // Add state to handle the accordion toggle
  const [isOpen, setIsOpen] = useState(false);

  const toggleAccordion = () => {
    setIsOpen(!isOpen);
  };

  // Check if it's an error object
  if (metasploitResults?.error) {
    return (
      <div className="bg-gray-900 rounded-xl p-6 shadow-lg mt-6">
        <h2 className="text-xl font-bold mb-4 text-white">Metasploit Vulnerability Results</h2>
        <p className="text-red-500 font-semibold">Error running Metasploit: {metasploitResults.error}</p>
      </div>
    );
  }

  // Extract the report array from the object sent by orchestrator.py
  const reportArray = metasploitResults?.report || [];

  if (!reportArray || reportArray.length === 0) {
    return (
      <div className="bg-gray-900 rounded-xl p-6 shadow-lg mt-6">
        <h2 className="text-xl font-bold mb-4 text-white">Metasploit Vulnerability Results</h2>
        <p className="text-gray-400">No Metasploit vulnerabilities detected or exploitation yielded no results.</p>
      </div>
    );
  }

  return (
    <div className="bg-gray-900 rounded-xl p-6 shadow-lg mt-6 ai-response-container">
      
      {/* Accordion Header */}
      <div 
        className="accordion-header flex justify-between items-center cursor-pointer mb-2" 
        onClick={toggleAccordion}
      >
        
        <h2 className="text-xl font-bold m-0" style={{ color: "white" }} > Metasploit AI Analysis Report </h2>
        <span 
          className={`accordion-icon text-white transform transition-transform duration-300 ${isOpen ? 'rotate-180' : ''}`}
        >
          &#9660;
        </span>
      </div>

      {/* Accordion Body */}
      {isOpen && (
        <div className="accordion-body mt-4 space-y-4">
          {reportArray.map((vuln, index) => (
            <div 
              key={index} 
              className="vulnerability-item bg-gray-800 border border-gray-700 rounded-lg p-5 transition hover:bg-gray-750"
            >
              <p className="text-red-400 mb-2">
                <strong className="text-white">⚠️ Vulnerability: </strong> 
                {vuln["Vulnerability"] || "N/A"}
              </p>
              
              <p className="text-gray-300 mb-2">
                <strong className="text-white">🖋️ Description: </strong> 
                {vuln["Description"] || "N/A"}
              </p>
              
              <p className="text-yellow-500 mb-2">
                <strong className="text-white">⚡ Impact: </strong> 
                {vuln["Impact"] || "N/A"}
              </p>
              
              <p className="text-blue-400 mb-2 break-words">
                <strong className="text-white">🔍 Sensitive Info Found: </strong> 
                {vuln["Sensitive information found"] || "None"}
              </p>
              
              <p className="text-green-400">
                <strong className="text-white">🛠️ Remediation: </strong> 
                {vuln["Remediation"] || "N/A"}
              </p>
            </div>
          ))}
        </div>
      )}
      
    </div>
  );
}