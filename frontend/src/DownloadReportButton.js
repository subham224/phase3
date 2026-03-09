import React, { useState } from 'react';
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';

const DownloadReportButton = ({ results, targetUrl, aiThreats }) => {
  const [isGenerating, setIsGenerating] = useState(false);

  const handleDownload = () => {
    setIsGenerating(true);
    
    setTimeout(() => {
      try {
        const doc = new jsPDF('p', 'pt', 'a4');
        const dateStr = new Date().toLocaleString();
        const pageWidth = doc.internal.pageSize.getWidth();
        const margin = 40;
        const maxTextWidth = pageWidth - (margin * 2);



        // --- TITLE PAGE / HEADER ---
        doc.setFontSize(22);
        doc.setTextColor(41, 128, 185); 
        doc.setFont("helvetica", "bold");
        doc.text("AI-Powered Security Scan Report", margin, 60);
        
        doc.setFontSize(12);
        doc.setTextColor(50, 50, 50);
        doc.setFont("helvetica", "normal");
        // doc.text(`Target URL: ${targetUrl || 'Unknown'}`, margin, 90);
        // doc.text(`Scan Date: ${dateStr}`, margin, 110);
        const firstWhatWeb = results?.whatweb_info?.[0] || {};
        const displayTarget = firstWhatWeb.target || targetUrl || 'Unknown';
        doc.text(`Target URL: ${displayTarget}`, margin, 90);

        // doc.text(`Scan Date: ${dateStr}`, margin, 110);

        let currentY = 140;

        // --- HELPER 1: Add Table (For short data like Ports/Subdomains) ---
        const addTableSection = (title, head, body) => {
          if (!body || body.length === 0) return;
          if (currentY > 750) { doc.addPage(); currentY = 40; } 
          
          doc.setFontSize(14);
          doc.setTextColor(0, 0, 0);
          doc.setFont("helvetica", "bold");
          doc.text(title, margin, currentY);
          
          autoTable(doc, {
            startY: currentY + 10,
            head: [head],
            body: body,
            theme: 'grid',
            headStyles: { fillColor: [41, 128, 185], textColor: 255, fontStyle: 'bold' },
            styles: { fontSize: 9, cellPadding: 4, overflow: 'linebreak' },
            margin: { left: margin, right: margin },
          });
          
          currentY = doc.lastAutoTable.finalY + 30;
        };

        // --- HELPER 2: Add Narrative (For long text like AI/Metasploit) ---
        const addNarrativeSection = (title, items) => {
          if (!items || items.length === 0) return;
          if (currentY > 750) { doc.addPage(); currentY = 40; }

          doc.setFontSize(16);
          doc.setTextColor(41, 128, 185);
          doc.setFont("helvetica", "bold");
          doc.text(title, margin, currentY);
          currentY += 25;

          items.forEach((item, index) => {
            const printParagraph = (label, text, color = [50, 50, 50]) => {
              if (!text || text === 'N/A') return;
              
              if (currentY > 780) { doc.addPage(); currentY = 40; }

              // Print Label (Bold)
              doc.setFontSize(11);
              doc.setFont("helvetica", "bold");
              doc.setTextColor(0, 0, 0);
              doc.text(`${label}:`, margin, currentY);
              currentY += 15;

              // Print Text (Normal, wrapped)
              doc.setFont("helvetica", "normal");
              doc.setTextColor(color[0], color[1], color[2]);
              const lines = doc.splitTextToSize(text, maxTextWidth);
              
              // Page break check for long text blocks
              if (currentY + (lines.length * 14) > 800) {
                doc.addPage();
                currentY = 40;
              }

              doc.text(lines, margin, currentY);
              currentY += (lines.length * 14) + 12; // Move down based on line count
            };

            printParagraph("Vulnerability", item.Vulnerability, [220, 38, 38]); // Red text for title
            printParagraph("Description", item.Description);
            printParagraph("Impact", item.Impact, [180, 83, 9]); // Orange text for impact
            printParagraph("Sensitive Information Found", item["Sensitive information found"], [37, 99, 235]); // Blue
            printParagraph("Remediation", item.Remediation, [22, 163, 74]); // Green text for remediation

            currentY += 10;

            // Draw a separator line between vulnerabilities
            if (index < items.length - 1) {
              if (currentY > 780) { doc.addPage(); currentY = 40; }
              doc.setDrawColor(200, 200, 200);
              doc.line(margin, currentY, pageWidth - margin, currentY);
              currentY += 20;
            }
          });
        };

        // ==========================================================
        // BUILD THE PDF SECTIONS
        // ==========================================================

        // --- 0. AI EXECUTIVE SUMMARY (Now uses Narrative format!) ---
        // if (aiThreats && aiThreats.length > 0) {
        //   addNarrativeSection("0. Combined AI Threat Analysis", aiThreats);
        // }

        // --- 1. WHATWEB ---
        if (results?.whatweb_info?.length > 0) {
          const wwBody = results.whatweb_info.map(w => [
            w.target || 'N/A', w.HTTPServer || 'N/A', w.IP || 'N/A'
          ]);
          addTableSection("1. WhatWeb Reconnaissance", ["Target", "Server", "IP"], wwBody);
        }

        // --- 2. SUBDOMAINS ---
        const subdomains = [];
        if (results?.harvester_info) subdomains.push(...results.harvester_info);
        if (results?.gobuster_info) subdomains.push(...results.gobuster_info);
        if (subdomains.length > 0) {
          const subBody = subdomains.map(s => [s.subdomain, s.resolved_ip || 'No IP', s.source]);
          addTableSection("2. Subdomain Enumeration", ["Subdomain"], subBody);
        }

        // --- 3. NMAP (Ports & Ciphers) ---
        if (results?.nmap_info && Object.keys(results.nmap_info).length > 0) {
          const allPorts = [];
          const uniqueCiphersMap = new Map();

          Object.values(results.nmap_info).forEach(scan => {
            if (scan && scan.hosts) {
              scan.hosts.forEach(host => {
                host.ports.forEach(port => {
                  allPorts.push({
                    host: host.address, portid: port.portid, protocol: port.protocol, state: port.state, service: port.service, reason: port.reason || 'N/A'
                  });
                  if (port.cipher_details && port.cipher_details.length > 0) {
                    port.cipher_details.forEach(cipher => {
                      const key = `${cipher.name}-${cipher.kex}-${cipher.auth}-${cipher.bits}-${cipher.strength}`;
                      if (!uniqueCiphersMap.has(key)) { uniqueCiphersMap.set(key, cipher); }
                    });
                  }
                });
              });
            }
          });

          if (allPorts.length > 0) {
            // const portBody = allPorts.map(p => [p.host || 'N/A', p.portid || 'N/A', p.protocol || 'N/A', p.state || 'N/A', p.service || 'N/A', p.reason || 'N/A']);

            const portBody = allPorts.map(p => [
  p.host || 'N/A', 
  p.portid || 'N/A', 
  p.protocol || 'N/A', 
  p.state || 'N/A', 
  p.service || 'N/A', 
  (p.reason === 'no-response' ? '--' : (p.reason || 'N/A'))
]);

            addTableSection("3. Nmap Ports Details", ["Host IP", "Port", "Protocol", "State", "Service","Reason"], portBody);
          }
          const uniqueCiphers = Array.from(uniqueCiphersMap.values());
          if (uniqueCiphers.length > 0) {
            const cipherBody = uniqueCiphers.map(c => [`${c.name || 'N/A'} ${c.raw_kex_auth ? `(${c.raw_kex_auth})` : ''}`, c.strength || 'N/A']);
            addTableSection("3.1 Nmap SSL Ciphers Details", ["Cipher Name", "Strength"], cipherBody);
          }
        }

        // --- 4. WAPITI VULNERABILITIES ---
        const wapitiVulns = results?.wapiti_info?.vulnerabilities || (Array.isArray(results?.wapiti_info) ? results.wapiti_info : []);
        if (wapitiVulns.length > 0) {
          const wBody = wapitiVulns.map(v => [v.category || v.info || 'N/A', v.level || 'N/A', (v.description || '').substring(0, 150) + "..."]);
          addTableSection("4. Wapiti Vulnerabilities", ["Category / Info"], wBody);
        }

        // // --- 5. SKIPFISH ISSUES ---
        // const skipfishVulns = results?.skipfish_info?.issue_samples || (Array.isArray(results?.skipfish_info) ? results.skipfish_info : []);
        // if (skipfishVulns.length > 0) {
        //   const sBody = skipfishVulns.map(s => [s.severity || s.risk || 'N/A', s.type || s.issue || 'N/A', s.url || 'N/A']);
        //   addTableSection("5. Skipfish Issues", ["Severity", "Issue Type", "Affected URL"], sBody);
        // }

        // --- 5. SKIPFISH ISSUES ---
        const skipfishDescriptions = {
          "10101": "SSL certificate issuer information", "10201": "New HTTP cookie added", "10202": "New 'Server' header value seen", "10203": "New 'Via' header value seen", "10204": "New 'X-*' header value seen", "10205": "New 404 signature seen", "10401": "Resource not directly accessible", "10402": "HTTP authentication required", "10403": "Server error triggered", "10404": "Directory listing enabled", "10405": "Hidden files / directories", "10501": "All external links", "10502": "External URL redirector", "10503": "All e-mail addresses", "10504": "Links to unknown protocols", "10505": "Unknown form field (can't autocomplete)", "10601": "HTML form (not classified otherwise)", "10602": "Password entry form - consider brute-force", "10603": "File upload form", "10701": "User-supplied link rendered on a page", "10801": "Incorrect or missing MIME type (low risk)", "10802": "Generic MIME used (low risk)", "10803": "Incorrect or missing charset (low risk)", "10804": "Conflicting MIME / charset info (low risk)", "10901": "Numerical filename - consider enumerating", "10902": "OGNL-like parameter behavior", "10909": "Signature match (informational)", "20101": "Resource fetch failed", "20102": "Limits exceeded, fetch suppressed", "20201": "Directory behavior checks failed (no brute force)", "20202": "Parent behavior checks failed (no brute force)", "20203": "IPS filtering enabled", "20204": "IPS filtering disabled again", "20205": "Response varies randomly, skipping checks", "20301": "Node should be a directory, detection error?", "30101": "HTTP credentials seen in URLs", "30201": "SSL certificate expired or not yet valid", "30202": "Self-signed SSL certificate", "30203": "SSL certificate host name mismatch", "30204": "No SSL certificate data found", "30205": "Weak SSL cipher negotiated", "30206": "Host name length mismatch (name string has null byte)", "30301": "Directory listing restrictions bypassed", "30401": "Redirection to attacker-supplied URLs", "30402": "Attacker-supplied URLs in embedded content (lower risk)", "30501": "External content embedded on a page (lower risk)", "30502": "Mixed content embedded on a page (lower risk)", "30503": "HTTPS form submitting to a HTTP URL", "30601": "HTML form with no apparent XSRF protection", "30602": "JSON response with no apparent XSSI protection", "30603": "Auth form leaks credentials via HTTP GET", "30701": "Incorrect caching directives (lower risk)", "30801": "User-controlled response prefix (BOM / plugin attacks)", "30901": "HTTP header injection vector", "30909": "Signature match detected", "40101": "XSS vector in document body", "40102": "XSS vector via arbitrary URLs", "40103": "HTTP response header splitting", "40104": "Attacker-supplied URLs in embedded content (higher risk)", "40105": "XSS vector via injected HTML tag attribute", "40201": "External content embedded on a page (higher risk)", "40202": "Mixed content embedded on a page (higher risk)", "40301": "Incorrect or missing MIME type (higher risk)", "40302": "Generic MIME type (higher risk)", "40304": "Incorrect or missing charset (higher risk)", "40305": "Conflicting MIME / charset info (higher risk)", "40401": "Interesting file", "40402": "Interesting server message", "40501": "Directory traversal / file inclusion possible", "40601": "Incorrect caching directives (higher risk)", "40701": "Password form submits from or to non-HTTPS page", "40909": "Signature match detected (high risk)", "50101": "Server-side XML injection vector", "50102": "Shell injection vector", "50103": "Query injection vector", "50104": "Format string vector", "50105": "Integer overflow vector", "50106": "File inclusion", "50107": "Remote file inclusion", "50201": "SQL query or similar syntax in parameters", "50301": "PUT request accepted", "50909": "Signature match detected (high risk)"
        };

        const skipfishVulns = results?.skipfish_info?.issue_samples || (Array.isArray(results?.skipfish_info) ? results.skipfish_info : []);
        if (skipfishVulns.length > 0) {
          const sBody = skipfishVulns.map(s => {
            const rawType = String(s.type || s.issue || '');
            const mappedDescription = skipfishDescriptions[rawType] || rawType || 'N/A';
            return [
              s.severity || s.risk || 'N/A', 
              mappedDescription, 
              s.url || 'N/A'
            ];
          });
          // Changed the header from "Issue Type" to "Description" to reflect the actual text
          addTableSection("5. Skipfish Issues", ["Severity", "Description", "Affected URL"], sBody);
        }

        // --- 6. SQLMAP FINDINGS ---
        const sqlmapVulns = results?.sqlmap_info?.vulnerabilities || (Array.isArray(results?.sqlmap_info) ? results.sqlmap_info : []);
        if (sqlmapVulns.length > 0) {
          const sqlBody = sqlmapVulns.map(s => [s.parameter || 'N/A', s.type || 'N/A', s.title || 'N/A']);
          addTableSection("6. SQLMap Injection Findings", ["Parameter", "Injection Type", "Title"], sqlBody);
        }


         // --- 7. AI EXECUTIVE SUMMARY (Now uses Narrative format!) ---
        if (aiThreats && aiThreats.length > 0) {
          addNarrativeSection("7. Combined AI Threat Analysis", aiThreats);
        }

        // --- 8. METASPLOIT AI REPORT (Now uses Narrative format!) ---
        if (results?.metasploit_info?.report && Array.isArray(results.metasploit_info.report)) {
          addNarrativeSection("8. Metasploit Exploitation Summary", results.metasploit_info.report);
        }

        // --- GENERATE FILENAME & SAVE ---
        let domain = "target";
        try {
          if (targetUrl) {
            const urlObj = new URL(targetUrl.startsWith('http') ? targetUrl : `http://${targetUrl}`);
            domain = urlObj.hostname.replace(/[^a-zA-Z0-9.-]/g, '_');
          }
        } catch (e) {}
        
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-').split('T')[0];
        doc.save(`scan_report_${domain}_${timestamp}.pdf`);

      } catch (err) {
        console.error("PDF Generation Error:", err);
        alert("An error occurred while generating the PDF. Check console for details.");
      } finally {
        setIsGenerating(false);
      }
    }, 100);
  };

  return (
    // ... exact same button JSX as before ...
    <button
      onClick={handleDownload}
      disabled={isGenerating}
      style={{ 
        position: 'fixed', top: '20px', right: '20px', zIndex: 999999,
        display: 'flex', alignItems: 'center', gap: '8px', padding: '10px 20px',
        borderRadius: '8px', fontWeight: 'bold', cursor: isGenerating ? 'not-allowed' : 'pointer',
        backgroundColor: isGenerating ? '#1e3a8a' : '#deeb25', color: '#070404', border: 'none',
        boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.5), 0 2px 4px -1px rgba(0, 0, 0, 0.3)',
        transition: 'all 0.2s ease-in-out'
      }}
      title="Download Scan Report as PDF"
      onMouseOver={(e) => { if(!isGenerating) e.currentTarget.style.transform = 'scale(1.05)' }}
      onMouseOut={(e) => { if(!isGenerating) e.currentTarget.style.transform = 'scale(1)' }}
    >
      {isGenerating ? (
        <svg style={{ animation: 'spin 1s linear infinite', height: '20px', width: '20px', color: '#000000' }} xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
          <circle style={{ opacity: 0.25 }} cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
          <path style={{ opacity: 0.75 }} fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
          <style>{`@keyframes spin { 100% { transform: rotate(360deg); } }`}</style>
        </svg>
      ) : (
        <svg style={{ width: '20px', height: '20px' }} fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
        </svg>
      )}
      <span style={{style: { color: '#000000'}}}>{isGenerating ? 'Generating PDF...' : 'Download Report'}</span>
    </button>
  );
};

export default DownloadReportButton;