// src/components/NmapHostAccordionItem.js
import React, { useState } from 'react';

/**
 * An accordion item for displaying a single Nmap host's details.
 * @param {Object} props - Component props.
 * @param {Object} props.host - Host data from an Nmap scan.
 * @param {string} props.scanType - The type of Nmap scan (e.g., 'deep_scan').
 */
function NmapHostAccordionItem({ host, scanType }) {
  const [isOpen, setIsOpen] = useState(false);

  const toggleAccordion = () => {
    setIsOpen(!isOpen);
  };

  return (
    <div className="accordion-item">
      <div className="accordion-header" onClick={toggleAccordion}>
        <h4>
          Host: {host.address} {host.hostname ? `(${host.hostname})` : ''}
          {host.os_details && <span> - OS: {host.os_details}</span>}
        </h4>
        <span className={`accordion-icon ${isOpen ? 'open' : ''}`}>&#9660;</span>
      </div>
      {isOpen && (
        <div className="accordion-content">
          {host.os_classes && host.os_classes.length > 0 && (
            <div>
              <h5>OS Classes:</h5>
              <ul>
                {host.os_classes.map((osClass, osIdx) => (
                  <li key={osIdx}>
                    OS Class: {osClass.osfamily || 'N/A'} {osClass.osgen || 'N/A'} (Vendor: {osClass.vendor || 'N/A'}, Type: {osClass.type || 'N/A'}, Accuracy: {osClass.accuracy || 'N/A'}%, CPE: {osClass.cpe || 'N/A'})
                  </li>
                ))}
              </ul>
            </div>
          )}
          {host.ports.length > 0 && (
            <div>
              <h5>Open Ports ({scanType.replace(/_/g, ' ').toUpperCase()}):</h5>
              <ul>
                {host.ports.filter(p => p.state === 'open').map((port, portIdx) => (
                  <li key={portIdx}>
                    Port {port.portid}/{port.protocol} - {port.service} ({port.state})
                    {port.product && ` - Product: ${port.product}`}
                    {port.version && ` - Version: ${port.version}`}
                    {port.reason && ` - Reason: ${port.reason}`}
                    {port.cipher_details && port.cipher_details.length > 0 && (
                      <ul>
                        <strong>Cipher Details:</strong>
                        {port.cipher_details.map((cipher, cipherIdx) => (
                          <li key={cipherIdx}>
                            {cipher.name} (Kex: {cipher.kex || 'N/A'}, Auth: {cipher.auth || 'N/A'}, Bits: {cipher.bits || 'N/A'}, Strength: {cipher.strength || 'N/A'})
                          </li>
                        ))}
                      </ul>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {Object.keys(host.scripts || {}).length > 0 && (
            <div>
              <h5>Host-Level Script Outputs:</h5>
              {Object.entries(host.scripts).map(([scriptId, scriptOutput], scriptIdx) => (
                <div key={scriptIdx}>
                  <strong>{scriptId}:</strong>
                  <pre>{scriptOutput}</pre>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default NmapHostAccordionItem;