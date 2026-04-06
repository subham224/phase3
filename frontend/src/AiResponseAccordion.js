// // src/components/AiResponseAccordion.js
// import React, { useState } from 'react';
// import './App.css'; // Assuming App.css is used for general styles

// const AiResponseAccordion = ({ title, vulnerabilities }) => {
//   const [isOpen, setIsOpen] = useState(false);

//   // Check if vulnerabilities exist and are an array
//   if (!vulnerabilities || !Array.isArray(vulnerabilities) || vulnerabilities.length === 0) {
//     return null;
//   }

//   const toggleAccordion = () => {
//     setIsOpen(!isOpen);
//   };

//   return (
//     <div className="ai-response-container">
//       <div className="accordion-header" onClick={toggleAccordion}>
//         <h3>Vulnerability Analysis</h3>
//         <span className={`accordion-icon ${isOpen ? 'open' : ''}`}>&#9660;</span>
//       </div>
//       {isOpen && (
//         <div className="accordion-body">
//           {vulnerabilities.map((vuln, index) => (
//             <div key={index} className="vulnerability-item">
//               {/*<h4>{vuln.Vulnerability}</h4>*/}
//               <p><strong>⚠️ Vulnerability:</strong>{vuln.Vulnerability}</p>
//               <p><strong>🖋️ Description:</strong> {vuln.Description}</p>
//               <p><strong>⚡ Impact:</strong> {vuln.Impact}</p>
//               <p><strong>🛠️ Remediation:</strong> {vuln.Remediation}</p>
//             </div>
//           ))}
//         </div>
//       )}
//     </div>
//   );
// };

// export default AiResponseAccordion;

// src/components/AiResponseAccordion.js
import React, { useState } from 'react';
import './App.css'; 

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
      <div 
        className="accordion-header" 
        onClick={toggleAccordion}
        style={{ cursor: 'pointer', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}
      >
        <h3 style={{ margin: 0 }}>Vulnerability Analysis</h3>
        <span className={`accordion-icon ${isOpen ? 'open' : ''}`} style={{ fontSize: '1.2rem' }}>
          {isOpen ? '▲' : '▼'}
        </span>
      </div>
      
      {isOpen && (
        <div className="accordion-body" style={{ marginTop: '20px' }}>
          {vulnerabilities.map((vuln, index) => (
            <div 
              key={index} 
              className="vulnerability-item single-card" 
              style={{
                backgroundColor: '#ffffff', // White background
                borderRadius: '10px',
                padding: '20px',
                marginBottom: '20px',
                border: '1px solid #e2e8f0', // Soft, light gray border
                boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)', // Softer drop shadow for light cards
                color: '#1e293b', // Dark slate text for perfect readability on white
                lineHeight: '1.6'
              }}
            >
              <p style={{ marginBottom: '12px' }}>
                <strong style={{ color: '#ef4444', fontSize: '1.05rem' }}>⚠️ Vulnerability: </strong>
                {vuln.Vulnerability}
              </p>
              
              <p style={{ marginBottom: '12px', whiteSpace: 'pre-wrap' }}>
                <strong style={{ color: '#2563eb', fontSize: '1.05rem' }}>🖋️ Description: </strong> 
                {vuln.Description}
              </p>
              
              <p style={{ marginBottom: '12px' }}>
                <strong style={{ color: '#ea580c', fontSize: '1.05rem' }}>⚡ Impact: </strong> 
                {vuln.Impact}
              </p>
              
              <p style={{ margin: 0, whiteSpace: 'pre-wrap' }}>
                <strong style={{ color: '#16a34a', fontSize: '1.05rem' }}>🛠️ Remediation: </strong> 
                {vuln.Remediation}
              </p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default AiResponseAccordion;