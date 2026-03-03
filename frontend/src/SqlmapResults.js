// src/SqlmapResults.js
import React from 'react';

const SqlmapResults = ({ data }) => {
  if (!data || !data.vulnerabilities || data.vulnerabilities.length === 0) {
    return (
      <div className="bg-gray-800 rounded-lg p-4 shadow-md mb-4 border border-gray-700">
        <h3 className="text-xl font-semibold text-green-400">SQLMap Database Scan</h3>
        <p className="text-gray-400 mt-2">No database vulnerabilities detected.</p>
      </div>
    );
  }

  return (
    <div className="bg-gray-800 rounded-lg shadow-md mb-4 overflow-hidden border border-gray-700">
      <div className="p-4 bg-gray-700 flex justify-between items-center border-b border-gray-600">
        <h3 className="text-xl font-semibold text-red-400 flex items-center gap-2">
          <span>SQLMap Vulnerabilities</span>
          <span className="bg-red-500/20 text-red-400 text-sm py-1 px-3 rounded-full">
            {/* {data.vulnerabilities.length} Found */}
          </span>
        </h3>
      </div>

      <div className="p-4 bg-gray-800 overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="bg-gray-900 text-gray-300">
              <th className="p-3 border-b border-gray-700">Place (Method)</th>
              <th className="p-3 border-b border-gray-700">Vulnerable Parameter</th>
              <th className="p-3 border-b border-gray-700">Injection Techniques</th>
              <th className="p-3 border-b border-gray-700">Target URL</th>
            </tr>
          </thead>
          <tbody>
            {data.vulnerabilities.map((vuln, index) => (
              <tr key={index} className="hover:bg-gray-700/50 transition-colors">
                <td className="p-3 border-b border-gray-700/50 text-orange-400 font-mono text-sm">{vuln.type}</td>
                <td className="p-3 border-b border-gray-700/50 text-blue-400 font-mono text-sm">{vuln.parameter}</td>
                <td className="p-3 border-b border-gray-700/50 text-gray-200">{vuln.title}</td>
                <td className="p-3 border-b border-gray-700/50 text-red-400 font-mono text-xs break-all bg-gray-900/50">{vuln.payload}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default SqlmapResults;