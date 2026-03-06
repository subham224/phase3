import React from "react";

const severityColor = (severity) => {
  switch (severity?.toLowerCase()) {
    case "critical":
      return "text-red-600 font-bold";
    case "high":
      return "text-orange-500 font-semibold";
    case "medium":
      return "text-yellow-500";
    case "low":
      return "text-green-500";
    default:
      return "text-gray-400";
  }
};

const exploitColor = (status) => {
  if (!status) return "text-gray-400";

  const val = status.toLowerCase();

  if (val.includes("exploitable"))
    return "text-red-500 font-semibold";

  if (val.includes("possible"))
    return "text-yellow-500";

  return "text-gray-400";
};

export default function MetasploitResults({ metasploitResults }) {

  if (!metasploitResults || metasploitResults.length === 0) {
    return (
      <div className="bg-gray-900 rounded-xl p-6 shadow-lg mt-6">
        <h2 className="text-xl font-bold mb-4 text-white">
          Metasploit Vulnerability Results
        </h2>

        <p className="text-gray-400">
          No Metasploit vulnerabilities detected.
        </p>
      </div>
    );
  }

  return (
    <div className="bg-gray-900 rounded-xl p-6 shadow-lg mt-6">

      <h2 className="text-xl font-bold mb-4 text-white">
        Metasploit Vulnerability Results
      </h2>

      <div className="overflow-x-auto">

        <table className="min-w-full border border-gray-700">

          <thead className="bg-gray-800 text-gray-200">
            <tr>
              <th className="px-4 py-2 border border-gray-700">Host</th>
              <th className="px-4 py-2 border border-gray-700">Port</th>
              <th className="px-4 py-2 border border-gray-700">Module</th>
              <th className="px-4 py-2 border border-gray-700">CVE</th>
              <th className="px-4 py-2 border border-gray-700">Severity</th>
              <th className="px-4 py-2 border border-gray-700">Exploitability</th>
              <th className="px-4 py-2 border border-gray-700">Description</th>
            </tr>
          </thead>

          <tbody>

            {metasploitResults.map((vuln, index) => (
              <tr
                key={index}
                className="hover:bg-gray-800 transition"
              >
                <td className="px-4 py-2 border border-gray-700 text-gray-200">
                  {vuln.host}
                </td>

                <td className="px-4 py-2 border border-gray-700 text-gray-200">
                  {vuln.port}
                </td>

                <td className="px-4 py-2 border border-gray-700 text-blue-400 break-all">
                  {vuln.module_name}
                </td>

                <td className="px-4 py-2 border border-gray-700 text-purple-400">
                  {vuln.cve || "N/A"}
                </td>

                <td
                  className={`px-4 py-2 border border-gray-700 ${severityColor(
                    vuln.severity
                  )}`}
                >
                  {vuln.severity}
                </td>

                <td
                  className={`px-4 py-2 border border-gray-700 ${exploitColor(
                    vuln.exploitability
                  )}`}
                >
                  {vuln.exploitability}
                </td>

                <td className="px-4 py-2 border border-gray-700 text-gray-300">
                  {vuln.description}
                </td>
              </tr>
            ))}

          </tbody>
        </table>

      </div>
    </div>
  );
}