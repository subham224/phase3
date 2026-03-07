import React from "react";

const severityColor = (severity) => {
  if (!severity) return "text-gray-400";
  const val = severity.toLowerCase();
  if (val.includes("high") || val.includes("critical")) return "text-red-500 font-bold";
  if (val.includes("medium")) return "text-yellow-500 font-semibold";
  if (val.includes("low")) return "text-green-500";
  return "text-gray-400";
};

export default function MetasploitResults({ metasploitResults }) {
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
    <div className="bg-gray-900 rounded-xl p-6 shadow-lg mt-6">
      <h2 className="text-xl font-bold mb-4 text-white">Metasploit AI Analysis Report</h2>
      <div className="overflow-x-auto">
        <table className="min-w-full border border-gray-700 text-sm">
          <thead className="bg-gray-800 text-gray-200">
            <tr>
              <th className="px-4 py-2 border border-gray-700">Vulnerability</th>
              <th className="px-4 py-2 border border-gray-700">Impact</th>
              <th className="px-4 py-2 border border-gray-700">Sensitive Info Found</th>
              <th className="px-4 py-2 border border-gray-700">Description</th>
              <th className="px-4 py-2 border border-gray-700">Remediation</th>
            </tr>
          </thead>
          <tbody>
            {reportArray.map((vuln, index) => (
              <tr key={index} className="hover:bg-gray-800 transition">
                <td className="px-4 py-2 border border-gray-700 text-red-400 font-semibold">
                  {vuln["Vulnerability"] || "N/A"}
                </td>
                <td className={`px-4 py-2 border border-gray-700 ${severityColor(vuln["Impact"])}`}>
                  {vuln["Impact"] || "N/A"}
                </td>
                <td className="px-4 py-2 border border-gray-700 text-yellow-400 break-words">
                  {vuln["Sensitive information found"] || "None"}
                </td>
                <td className="px-4 py-2 border border-gray-700 text-gray-300">
                  {vuln["Description"] || "N/A"}
                </td>
                <td className="px-4 py-2 border border-gray-700 text-green-400">
                  {vuln["Remediation"] || "N/A"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}